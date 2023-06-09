//! Windows certificate store wrapper

use std::{os::raw::c_void, ptr};

use widestring::U16CString;
use windows::{core::PCWSTR, Win32::Security::Cryptography::*};

use crate::{cert::CertContext, error::CngError};

const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0);

/// Certificate store type
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd)]
pub enum CertStoreType {
    LocalMachine,
    CurrentUser,
    CurrentService,
}

impl CertStoreType {
    fn as_flags(&self) -> u32 {
        match self {
            CertStoreType::LocalMachine => {
                CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            CertStoreType::CurrentUser => {
                CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            CertStoreType::CurrentService => {
                CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
        }
    }
}

/// Windows certificate store wrapper
#[derive(Debug)]
pub struct CertStore(HCERTSTORE);

unsafe impl Send for CertStore {}
unsafe impl Sync for CertStore {}

impl CertStore {
    /// Return an inner handle to the store
    pub fn inner(&self) -> HCERTSTORE {
        self.0
    }

    /// Open certificate store of the given type and name
    pub fn open(store_type: CertStoreType, store_name: &str) -> Result<CertStore, CngError> {
        unsafe {
            let store_name = U16CString::from_str_unchecked(store_name);
            let handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE::default(),
                HCRYPTPROV_LEGACY::default(),
                CERT_OPEN_STORE_FLAGS(store_type.as_flags() | CERT_STORE_OPEN_EXISTING_FLAG.0),
                Some(store_name.as_ptr() as _),
            )?;
            Ok(CertStore(handle))
        }
    }

    /// Open certificate store of the given type and name. Returned store is only used
    /// for optimized sha1 find.
    pub fn open_for_sha1_find(store_type: CertStoreType, store_name: &str) -> Result<CertStore, CngError> {
        unsafe {
            let store_name = U16CString::from_str_unchecked(store_name);
            let handle = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE::default(),
                HCRYPTPROV_LEGACY::default(),
                CERT_OPEN_STORE_FLAGS(store_type.as_flags()
                    | CERT_STORE_OPEN_EXISTING_FLAG.0
                    | CERT_SYSTEM_STORE_DEFER_READ_FLAG,
                ),
                Some(store_name.as_ptr() as _),
            )?;
            Ok(CertStore(handle))
        }
    }

    pub fn get_bytes_property(&self, property: u32) -> Result<Vec<u8>, CngError> {
        let mut result: u32 = 0;

        unsafe {
            let ret = CertGetStoreProperty(
                self.inner(),
                property,
                None,
                &mut result
            );
            if !ret.as_bool() {
                return Err(CngError::InvalidCertificateProperty);
            }

            let mut prop_value = vec![0u8; result as usize];

            let ret = CertGetStoreProperty(
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

    pub fn is_local_machine(&self) -> bool {
        let empty_vec = vec![0u8; 0];
        let prop = self.get_bytes_property(CERT_ACCESS_STATE_PROP_ID).unwrap_or(empty_vec);

        let store_flag: u8 = CERT_ACCESS_STATE_LM_SYSTEM_STORE_FLAG as u8;
        if prop.len() == 0 || 0 == (prop[0] & store_flag) {
            false
        } else {
            true
        }
    }

    pub fn set_auto_resync(&self) -> Result<(), CngError> {
        unsafe {
            let ret = CertControlStore(
                self.inner(),
                CERT_CONTROL_STORE_FLAGS::default(),
                CERT_STORE_CTRL_AUTO_RESYNC,
                None
            );
            if !ret.as_bool() {
                Err(CngError::UnsupportedStoreOperation)
            } else {
                Ok(())
            }
        }
    }

    /// Import certificate store from PKCS12 file
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<CertStore, CngError> {
        unsafe {
            let blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as _,
            };

            let password = U16CString::from_str_unchecked(password);
            let store = PFXImportCertStore(
                &blob,
                PCWSTR(password.as_ptr()),
                CRYPT_EXPORTABLE | PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_PREFER_CNG_KSP,
            )?;
            Ok(CertStore(store))
        }
    }

    /// Find list of certificates matching the subject substring
    pub fn find_by_subject_str<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_str(subject.as_ref(), CERT_FIND_SUBJECT_STR)
    }

    /// Find list of certificates matching the exact subject name
    pub fn find_by_subject_name<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_name(subject.as_ref(), CERT_FIND_SUBJECT_NAME)
    }

    /// Find list of certificates matching the issuer substring
    pub fn find_by_issuer_str<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_str(subject.as_ref(), CERT_FIND_ISSUER_STR)
    }

    /// Find list of certificates matching the exact issuer name
    pub fn find_by_issuer_name<S>(&self, subject: S) -> Result<Vec<CertContext>, CngError>
    where
        S: AsRef<str>,
    {
        self.find_by_name(subject.as_ref(), CERT_FIND_ISSUER_NAME)
    }

    /// Find list of certificates matching the SHA1 hash
    pub fn find_by_sha1<D>(&self, hash: D) -> Result<Vec<CertContext>, CngError>
    where
        D: AsRef<[u8]>,
    {
        let hash_blob = CRYPT_INTEGER_BLOB {
            cbData: hash.as_ref().len() as u32,
            pbData: hash.as_ref().as_ptr() as _,
        };
        self.do_find(CERT_FIND_HASH, &hash_blob as *const _ as _)
    }

    /// Get all certificates
    pub fn find_all(&self) -> Result<Vec<CertContext>, CngError> {
        self.do_find(CERT_FIND_ANY, ptr::null())
    }

    fn do_find(
        &self,
        flags: CERT_FIND_FLAGS,
        find_param: *const c_void,
    ) -> Result<Vec<CertContext>, CngError> {
        let mut certs = Vec::new();

        let mut cert: *mut CERT_CONTEXT = ptr::null_mut();

        loop {
            cert = unsafe {
                CertFindCertificateInStore(
                    self.0,
                    MY_ENCODING_TYPE,
                    0,
                    flags,
                    Some(find_param),
                    Some(cert),
                )
            };
            if cert.is_null() {
                break;
            } else {
                // increase refcount because it will be released by next call to CertFindCertificateInStore
                let cert = unsafe { CertDuplicateCertificateContext(Some(cert)) };
                certs.push(CertContext::new_owned(cert))
            }
        }
        Ok(certs)
    }

    fn find_by_str(
        &self,
        pattern: &str,
        flags: CERT_FIND_FLAGS,
    ) -> Result<Vec<CertContext>, CngError> {
        let u16pattern = unsafe { U16CString::from_str_unchecked(pattern) };
        self.do_find(flags, u16pattern.as_ptr() as _)
    }

    fn find_by_name(
        &self,
        field: &str,
        flags: CERT_FIND_FLAGS,
    ) -> Result<Vec<CertContext>, CngError> {
        let mut name_size = 0;

        unsafe {
            let field_name = U16CString::from_str_unchecked(field);
            if !CertStrToNameW(
                MY_ENCODING_TYPE,
                PCWSTR(field_name.as_ptr()),
                CERT_X500_NAME_STR,
                None,
                None,
                &mut name_size,
                None,
            )
            .as_bool()
            {
                return Err(CngError::from_win32_error());
            }

            let mut x509name = vec![0u8; name_size as usize];
            if !CertStrToNameW(
                MY_ENCODING_TYPE,
                PCWSTR(field_name.as_ptr()),
                CERT_X500_NAME_STR,
                None,
                Some(x509name.as_mut_ptr()),
                &mut name_size,
                None,
            )
            .as_bool()
            {
                return Err(CngError::from_win32_error());
            }

            let name_blob = CRYPT_INTEGER_BLOB {
                cbData: x509name.len() as u32,
                pbData: x509name.as_ptr() as _,
            };

            self.do_find(flags, &name_blob as *const _ as _)
        }
    }

    /// Find first certificate matching the SHA1 hash
    pub fn find_first_by_sha1<D>(&self, hash: D) -> Result<CertContext, CngError>
    where
        D: AsRef<[u8]>,
    {
        let contexts = self.find_by_sha1(hash)?;
        if contexts.len() == 0 {
            return Err(CngError::NotFoundCertificate);
        }

        let context = &contexts[0];

        let cert = unsafe { CertDuplicateCertificateContext(Some(context.inner())) };
        Ok(CertContext::new_owned(cert))
    }

    /// Find list of certificates matching the SHA1 hash
    pub fn find_last_renewed<D>(&self, hash: D) -> Result<CertContext, CngError>
    where
        D: AsRef<[u8]>,
    {
        const SHA1_LENGTH: usize = 20;
        const SHA256_LENGTH: usize = 32;
 
        let hash = hash.as_ref();

        if hash.len() != SHA1_LENGTH && hash.len() != (SHA1_LENGTH + SHA256_LENGTH) {
            return Err(CngError::InvalidHashLength);
        }

        let mut context = self.find_first_by_sha1(&hash[0 .. SHA1_LENGTH])?;

        if hash.len() == (SHA1_LENGTH + SHA256_LENGTH) {
            let sha256_hash = context.get_bytes_property(CERT_SHA256_HASH_PROP_ID)?;
            if &hash[SHA1_LENGTH .. SHA1_LENGTH + SHA256_LENGTH] != sha256_hash {
                return Err(CngError::NotFoundCertificate);
            }
        }

        //
        // From schannel
        //
        // Loop through the linked list of renewed certificates, looking
        // for the last one. Do not exceed the max links, as we can get in an infinite
        // loop if the cert has renewal property pointing to itself. As such, assuming
        // certiciate update every 8 hours for up to 1 year, gives us about a 1000 certs
        // in the chain of renewals. Giving it a bit more room is a reasonable compromise.
        //
        const MAX_RENEWAL_LINKS_TO_CHASE: usize = 1338;
        let mut renew_count: usize = 0;

        loop {
            let empty_vec = vec![0u8; 0];

            let renewed_hash = context.get_bytes_property(CERT_RENEWAL_PROP_ID).unwrap_or(empty_vec);
            if renewed_hash.len() != SHA1_LENGTH {
                break;
            }

            match self.find_first_by_sha1(renewed_hash) {
                Ok(renew_context) => {
                    context = renew_context;
                }

                Err(_err) => {
                    break;
                }
            }

            renew_count += 1;
            if renew_count > MAX_RENEWAL_LINKS_TO_CHASE {
                break;
            }
        }

        Ok(context)
    }

    pub fn find_client_cert(&self, acceptable_issuers: &[&[u8]]) -> Result<CertContext, CngError>
    {
        for x509name in acceptable_issuers {
            let name_blob = CRYPT_INTEGER_BLOB {
                cbData: x509name.len() as u32,
                pbData: x509name.as_ptr() as _,
            };

            let contexts = self.do_find(CERT_FIND_ISSUER_NAME, &name_blob as *const _ as _)?;
            for context in contexts {
                if context.has_private_key() && context.is_time_valid() {
                    return Ok(context);
                }
            }
        }

        Err(CngError::NotFoundCertificate)
    }


}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe { CertCloseStore(self.0, 0) };
    }
}

impl Clone for CertStore {
    fn clone(&self) -> CertStore {
        unsafe { CertStore(CertDuplicateStore(self.0)) }
    }
}
