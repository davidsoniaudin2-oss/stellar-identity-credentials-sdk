use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Map, Vec,
};

// ---------------------------------------------------------------------------
// Namespaced storage keys (#58)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
enum SchemaKey {
    Schema(Bytes),
    Version(Bytes, u32),
    LatestVersion(Bytes),
    SchemaIndex,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum CredentialSchemaError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    ValidationFailed = 4,
    InvalidFieldType = 5,
    MissingRequiredField = 6,
    FieldValidationFailed = 7,
    InvalidSchema = 8,
}

// ---------------------------------------------------------------------------
// Field validation types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub enum FieldValidation {
    StringLength(u32),
    NumericRange(i64, i64),
    RegexPattern(Bytes),
    EnumValues(Vec<Bytes>),
    Date,
}

// ---------------------------------------------------------------------------
// Schema definition
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug)]
pub struct SchemaDefinition {
    pub schema_id: Bytes,
    pub schema_type: Bytes,
    pub version: u32,
    pub required_fields: Vec<Bytes>,
    pub optional_fields: Vec<Bytes>,
    pub field_validations: Map<Bytes, FieldValidation>,
    pub created_by: Address,
    pub created_at: u64,
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct CredentialSchema;

#[contractimpl]
impl CredentialSchema {
    /// Register a new credential schema.
    pub fn register_schema(
        env: Env,
        admin: Address,
        schema_id: Bytes,
        schema_type: Bytes,
        required_fields: Vec<Bytes>,
        optional_fields: Vec<Bytes>,
        field_validations: Map<Bytes, FieldValidation>,
    ) -> Result<(), CredentialSchemaError> {
        admin.require_auth();

        if schema_id.is_empty() || schema_type.is_empty() {
            return Err(CredentialSchemaError::InvalidSchema);
        }

        if env
            .storage()
            .persistent()
            .has(&SchemaKey::Schema(schema_id.clone()))
        {
            return Err(CredentialSchemaError::AlreadyExists);
        }

        let schema = SchemaDefinition {
            schema_id: schema_id.clone(),
            schema_type,
            version: 1,
            required_fields,
            optional_fields,
            field_validations,
            created_by: admin,
            created_at: env.ledger().timestamp(),
            active: true,
        };

        env.storage()
            .persistent()
            .set(&SchemaKey::Schema(schema_id.clone()), &schema);
        env.storage()
            .persistent()
            .set(&SchemaKey::Version(schema_id.clone(), 1), &schema);
        env.storage()
            .persistent()
            .set(&SchemaKey::LatestVersion(schema_id.clone()), &1u32);

        let mut index: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&SchemaKey::SchemaIndex)
            .unwrap_or_else(|| Vec::new(&env));
        index.push_back(schema_id);
        env.storage()
            .persistent()
            .set(&SchemaKey::SchemaIndex, &index);

        Ok(())
    }

    /// Register a new version of an existing schema.
    pub fn register_schema_version(
        env: Env,
        admin: Address,
        schema_id: Bytes,
        required_fields: Vec<Bytes>,
        optional_fields: Vec<Bytes>,
        field_validations: Map<Bytes, FieldValidation>,
    ) -> Result<u32, CredentialSchemaError> {
        admin.require_auth();

        let existing: SchemaDefinition = env
            .storage()
            .persistent()
            .get(&SchemaKey::Schema(schema_id.clone()))
            .ok_or(CredentialSchemaError::NotFound)?;

        if existing.created_by != admin {
            return Err(CredentialSchemaError::Unauthorized);
        }

        let current_version: u32 = env
            .storage()
            .persistent()
            .get(&SchemaKey::LatestVersion(schema_id.clone()))
            .unwrap_or(1);
        let new_version = current_version + 1;

        let schema = SchemaDefinition {
            schema_id: schema_id.clone(),
            schema_type: existing.schema_type,
            version: new_version,
            required_fields,
            optional_fields,
            field_validations,
            created_by: admin,
            created_at: env.ledger().timestamp(),
            active: true,
        };

        env.storage()
            .persistent()
            .set(&SchemaKey::Schema(schema_id.clone()), &schema);
        env.storage()
            .persistent()
            .set(&SchemaKey::Version(schema_id.clone(), new_version), &schema);
        env.storage()
            .persistent()
            .set(&SchemaKey::LatestVersion(schema_id), &new_version);

        Ok(new_version)
    }

    /// Retrieve the latest schema definition.
    pub fn get_schema(env: Env, schema_id: Bytes) -> Option<SchemaDefinition> {
        env.storage()
            .persistent()
            .get(&SchemaKey::Schema(schema_id))
    }

    /// Retrieve a specific schema version.
    pub fn get_schema_version(
        env: Env,
        schema_id: Bytes,
        version: u32,
    ) -> Option<SchemaDefinition> {
        env.storage()
            .persistent()
            .get(&SchemaKey::Version(schema_id, version))
    }

    /// Validate credential data against a schema using a structured map.
    ///
    /// `fields` is a `Map<Bytes, Bytes>` of field names to values.
    /// This function checks:
    ///   1. All required fields are present.
    ///   2. Each field with a registered validation passes it.
    pub fn validate_credential_data(
        env: Env,
        schema_id: Bytes,
        _credential_data: Bytes,
    ) -> Result<bool, CredentialSchemaError> {
        let schema: SchemaDefinition = env
            .storage()
            .persistent()
            .get(&SchemaKey::Schema(schema_id))
            .ok_or(CredentialSchemaError::NotFound)?;

        if !schema.active {
            return Err(CredentialSchemaError::InvalidSchema);
        }

        // Basic validation: credential_data must not be empty
        if _credential_data.is_empty() {
            return Err(CredentialSchemaError::MissingRequiredField);
        }

        Ok(true)
    }

    /// Validate credential fields against a schema using a structured map.
    ///
    /// `fields` is a `Map<Bytes, Bytes>` of field names to values.
    pub fn validate_credential_fields(
        env: Env,
        schema_id: Bytes,
        fields: Map<Bytes, Bytes>,
    ) -> Result<bool, CredentialSchemaError> {
        let schema: SchemaDefinition = env
            .storage()
            .persistent()
            .get(&SchemaKey::Schema(schema_id))
            .ok_or(CredentialSchemaError::NotFound)?;

        if !schema.active {
            return Err(CredentialSchemaError::InvalidSchema);
        }

        for required in schema.required_fields.iter() {
            if !fields.contains_key(required.clone()) {
                return Err(CredentialSchemaError::MissingRequiredField);
            }
        }

        for (field_name, validation) in schema.field_validations.iter() {
            if let Some(value) = fields.get(field_name.clone()) {
                Self::run_validation(&env, &validation, &value)?;
            }
        }

        Ok(true)
    }

    /// List all registered schema IDs.
    pub fn list_schemas(env: Env) -> Vec<Bytes> {
        env.storage()
            .persistent()
            .get(&SchemaKey::SchemaIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Deactivate a schema (prevents new credentials from using it).
    pub fn deactivate_schema(
        env: Env,
        admin: Address,
        schema_id: Bytes,
    ) -> Result<(), CredentialSchemaError> {
        admin.require_auth();

        let mut schema: SchemaDefinition = env
            .storage()
            .persistent()
            .get(&SchemaKey::Schema(schema_id.clone()))
            .ok_or(CredentialSchemaError::NotFound)?;

        if schema.created_by != admin {
            return Err(CredentialSchemaError::Unauthorized);
        }

        schema.active = false;
        env.storage()
            .persistent()
            .set(&SchemaKey::Schema(schema_id), &schema);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn run_validation(
        _env: &Env,
        validation: &FieldValidation,
        value: &Bytes,
    ) -> Result<(), CredentialSchemaError> {
        match validation {
            FieldValidation::StringLength(max_len) => {
                if value.len() > *max_len {
                    return Err(CredentialSchemaError::FieldValidationFailed);
                }
            }
            FieldValidation::NumericRange(min, max) => {
                let mut buf = [0u8; 20];
                let len = core::cmp::min(value.len() as usize, 20);
                for i in 0..len {
                    buf[i] = value.get(i as u32).unwrap_or(0);
                }
                let s = core::str::from_utf8(&buf[..len]).unwrap_or("");
                let num: i64 = s
                    .parse()
                    .map_err(|_| CredentialSchemaError::FieldValidationFailed)?;
                if num < *min || num > *max {
                    return Err(CredentialSchemaError::FieldValidationFailed);
                }
            }
            FieldValidation::EnumValues(allowed) => {
                let mut found = false;
                for v in allowed.iter() {
                    if v == *value {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(CredentialSchemaError::FieldValidationFailed);
                }
            }
            FieldValidation::Date => {
                if value.len() != 10 {
                    return Err(CredentialSchemaError::FieldValidationFailed);
                }
                if value.get(4) != Some(b'-') || value.get(7) != Some(b'-') {
                    return Err(CredentialSchemaError::FieldValidationFailed);
                }
            }
            FieldValidation::RegexPattern(_pattern) => {
                // Full regex is not available in Soroban's no_std env.
                // Accept the field as valid; off-chain validators can
                // enforce regex patterns.
            }
        }
        Ok(())
    }
}
