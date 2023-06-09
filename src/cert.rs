//! Wrapper struct for Windows CERT_CONTEXT

use std::{mem, ptr, slice, sync::Arc};
use std::{os::raw::c_void};

use windows::Win32::Security::Cryptography::*;

use crate::{error::CngError, key::NCryptKey, store::CertStore};

#[derive(Debug)]
enum InnerContext {
    Owned(*const CERT_CONTEXT),
    Borrowed(*const CERT_CONTEXT),
}

unsafe impl Send for InnerContext {}
unsafe impl Sync for InnerContext {}

impl InnerContext {
    fn inner(&self) -> *const CERT_CONTEXT {
        match self {
            Self::Owned(handle) => *handle,
            Self::Borrowed(handle) => *handle,
        }
    }
}

impl Drop for InnerContext {
    fn drop(&mut self) {
        match self {
            Self::Owned(handle) => unsafe {
                CertFreeCertificateContext(Some(*handle));
            },
            Self::Borrowed(_) => {}
        }
    }
}

/// Certificate chain engine type
///
/// Normally this would be CurrentUserEngine. It would be set to
/// LocalMachineEngine if the certificate was found in the LocalMachine "My"
/// and CA intermediate certificates are also in the LocalMachine "My" store.
/// Unlike other stores, the CurrentUser "My" doesn't inherit from LocalMachine.
///
/// #define HCCE_CURRENT_USER           ((HCERTCHAINENGINE)NULL)
/// #define HCCE_LOCAL_MACHINE          ((HCERTCHAINENGINE)0x1)
pub const HCCE_CURRENT_USER: isize = 0isize;
pub const HCCE_LOCAL_MACHINE: isize = 1isize;

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum CertChainEngineType {
    CurrentUser,
    LocalMachine,
}

/// AIA retrieval type
///
/// Normally, we would expect the CA certificates to already be in the "CA".
/// However, if that isn't the case, would want to enable Wire retrieval.
///
/// You would set to CacheOnlyRetrieval to always prevent any potential
/// network retrievals.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum CertAiaRetrievalType {
    Network,
    CacheOnly,
}

/// CertContext wraps CERT_CONTEXT structure for high-level certificate operations
#[derive(Debug, Clone)]
pub struct CertContext(Arc<InnerContext>);

impl CertContext {
    /// Construct CertContext as an owned object which automatically frees the inner handle
    pub fn new_owned(context: *const CERT_CONTEXT) -> Self {
        Self(Arc::new(InnerContext::Owned(context)))
    }

    /// Construct CertContext as a borrowed object which does not free the inner handle
    pub fn new_borrowed(context: *const CERT_CONTEXT) -> Self {
        Self(Arc::new(InnerContext::Borrowed(context)))
    }

    /// Return a reference to the inner handle
    pub fn inner(&self) -> &CERT_CONTEXT {
        unsafe { &*self.0.inner() }
    }

    /// Attempt to silently acquire a CNG private key from this context.
    pub fn acquire_key(&self) -> Result<NCryptKey, CngError> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut key_spec = CERT_KEY_SPEC::default();
        let flags =
            CRYPT_ACQUIRE_FLAGS(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG) | CRYPT_ACQUIRE_SILENT_FLAG;
        unsafe {
            let result = CryptAcquireCertificatePrivateKey(
                self.inner(),
                flags,
                None,
                &mut handle,
                Some(&mut key_spec),
                None,
            )
            .as_bool();
            if result {
                Ok(NCryptKey::new_owned(NCRYPT_KEY_HANDLE(handle.0)))
            } else {
                Err(CngError::from_win32_error())
            }
        }
    }

    /// Return DER-encoded X.509 certificate
    pub fn as_der(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.inner().pbCertEncoded,
                self.inner().cbCertEncoded as usize,
            )
        }
    }

    /// Return DER-encoded X.509 certificate chain
    pub fn as_chain_der_orig(&self) -> Result<Vec<Vec<u8>>, CngError> {
        unsafe {
            let param = CERT_CHAIN_PARA {
                cbSize: mem::size_of::<CERT_CHAIN_PARA>() as u32,
                RequestedUsage: Default::default(),
            };

            let mut context: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

            let result = CertGetCertificateChain(
                HCERTCHAINENGINE::default(),
                self.inner(),
                None,
                HCERTSTORE::default(),
                &param,
                0,
                None,
                &mut context,
            );

            if result.as_bool() {
                let mut chain = vec![];

                if (*context).cChain > 0 {
                    let chain_ptr = *(*context).rgpChain;
                    let elements = slice::from_raw_parts(
                        (*chain_ptr).rgpElement,
                        (*chain_ptr).cElement as usize,
                    );
                    for element in elements {
                        let context = (**element).pCertContext;
                        chain.push(Self::new_borrowed(context).as_der().to_vec());
                    }
                }

                CertFreeCertificateChain(&*context);

                Ok(chain)
            } else {
                Err(CngError::InvalidCertificateChain)
            }
        }
    }


    /// Return DER-encoded X.509 certificate chain
    pub fn as_chain_der(&self) -> Result<Vec<Vec<u8>>, CngError> {
        self.as_chain_der_ex(
            CertChainEngineType::CurrentUser,
            CertAiaRetrievalType::Network,
            false,                          // include_root
            None)                           // additional_store
    }

    /// Return DER-encoded X.509 certificate chain
    ///
    /// The additional_store should be provided if the CA certicates
    /// aren't in the default CA store. Note, this store shouldn't
    /// be opened via open_for_sha1_find().
    /// 
    pub fn as_chain_der_ex(
                &self,
                chain_engine_type: CertChainEngineType,
                aia_retrieval_type: CertAiaRetrievalType,
                include_root: bool,
                additional_store: Option<CertStore>
           ) -> Result<Vec<Vec<u8>>, CngError> {
        unsafe {
            let param = CERT_CHAIN_PARA {
                cbSize: mem::size_of::<CERT_CHAIN_PARA>() as u32,
                RequestedUsage: Default::default(),
            };

            let store = match additional_store {
                Some(store) => store.inner(),
                None => HCERTSTORE::default(),
            };

            let mut engine = HCERTCHAINENGINE::default();
            match chain_engine_type {
                CertChainEngineType::CurrentUser => engine.0 = HCCE_CURRENT_USER,
                CertChainEngineType::LocalMachine => engine.0 = HCCE_LOCAL_MACHINE,
            };

            let flags = match aia_retrieval_type {
                CertAiaRetrievalType::Network => 0u32,
                CertAiaRetrievalType::CacheOnly => CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
            };
                
            let mut context: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

            let result = CertGetCertificateChain(
                engine,
                self.inner(),
                None,
                store,
                &param,
                flags,
                None,
                &mut context,
            );

            if result.as_bool() {
                let mut chain = vec![];

                if (*context).cChain > 0 {
                    let chain_ptr = *(*context).rgpChain;
                    let elements = slice::from_raw_parts(
                        (*chain_ptr).rgpElement,
                        (*chain_ptr).cElement as usize,
                    );

                    let mut first = true;
                    for element in elements {
                        if first {
                            first = false;
                        } else if !include_root {
                            if 0 != ((**element).TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED) {
                                break;
                            }
                        }

                        let context = (**element).pCertContext;
                        chain.push(Self::new_borrowed(context).as_der().to_vec());
                    }
                }

                CertFreeCertificateChain(&*context);

                Ok(chain)
            } else {
                Err(CngError::InvalidCertificateChain)
            }
        }
    }

    pub fn get_bytes_property(&self, property: u32) -> Result<Vec<u8>, CngError> {
        let mut result: u32 = 0;

        unsafe {
            let ret = CertGetCertificateContextProperty(
                self.inner(),
                property,
                None,
                &mut result
            );
            if !ret.as_bool() {
                return Err(CngError::InvalidCertificateProperty);
            }

            let mut prop_value = vec![0u8; result as usize];

            let ret = CertGetCertificateContextProperty(
                self.inner(),
                property,
                Some(prop_value.as_mut_ptr() as *mut c_void),
                &mut result
            );

            if ret.as_bool() {
                Ok(prop_value)
            } else {
                Err(CngError::InvalidCertificateProperty)
            }
        }
    }

    pub fn has_private_key(&self) -> bool {
        let mut result: u32 = 0;

        unsafe {
            CertGetCertificateContextProperty(
                self.inner(),
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &mut result).as_bool()
        }
    }

    pub fn is_time_valid(&self) -> bool {
        unsafe {
            let ret = CertVerifyTimeValidity(
                None,
                self.inner().pCertInfo);
            if ret == 0 {
                true
            } else {
                false
            }
        }
    }
}
