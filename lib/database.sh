#!/bin/bash
#
# database.sh - Database setup for OpenEFA
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Secure MariaDB installation (mysql_secure_installation equivalent)
#
secure_mariadb() {
    info "Securing MariaDB installation..."

    # Set root password and remove anonymous users
    mysql -u root << EOSQL >> "${LOG_FILE}" 2>&1
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOSQL

    if [[ $? -eq 0 ]]; then
        success "MariaDB secured"
        return 0
    else
        error "Failed to secure MariaDB"
        return 1
    fi
}

#
# Create database and user
#
create_database_and_user() {
    section "Creating Database and User"

    info "Database: ${DB_NAME}"
    info "User: ${DB_USER}"

    mysql -u root << EOSQL >> "${LOG_FILE}" 2>&1
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT SELECT ON mysql.proc TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOSQL

    if [[ $? -eq 0 ]]; then
        success "Database and user created"
        save_state "database_created"
        return 0
    else
        error "Failed to create database and user"
        return 1
    fi
}

#
# Import database schema
#
import_database_schema() {
    info "Importing database schema..."

    local schema_file="${SCRIPT_DIR}/sql/schema_v1.sql"

    if [[ ! -f "${schema_file}" ]]; then
        error "Schema file not found: ${schema_file}"
        return 1
    fi

    # Import as root to handle views with DEFINER clauses
    if mysql -u root "${DB_NAME}" < "${schema_file}" >> "${LOG_FILE}" 2>&1; then
        success "Main database schema imported"

        # Import quarantine schema if it exists
        local quarantine_schema="${SCRIPT_DIR}/sql/quarantine_schema.sql"
        if [[ -f "${quarantine_schema}" ]]; then
            info "Importing quarantine schema..."
            if mysql -u root "${DB_NAME}" < "${quarantine_schema}" >> "${LOG_FILE}" 2>&1; then
                success "Quarantine schema imported"
            else
                warning "Failed to import quarantine schema (non-fatal)"
            fi
        fi

        # Grant permissions to spacy_user after import
        mysql -u root << EOSQL >> "${LOG_FILE}" 2>&1
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOSQL
        success "Database schema imported"
        save_state "schema_imported"
        return 0
    else
        error "Failed to import database schema"
        return 1
    fi
}

#
# Create .my.cnf configuration file
#
create_mysql_config() {
    info "Creating MySQL configuration file..."

    local config_dir="/opt/spacyserver/config"
    local config_file="${config_dir}/.my.cnf"

    create_directory "${config_dir}" "spacy-filter:spacy-filter" "750"

    cat > "${config_file}" << EOMYCNF
[client]
user = ${DB_USER}
password = ${DB_PASSWORD}
host = localhost
database = ${DB_NAME}

[mysql]
database = ${DB_NAME}
EOMYCNF

    chown spacy-filter:spacy-filter "${config_file}"
    chmod 600 "${config_file}"

    success "MySQL config created: ${config_file}"
    save_state "mysql_config_created"
    return 0
}

#
# Insert initial domain into client_domains table
#
insert_initial_domain() {
    # Insert multiple domains if array is populated
    if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
        info "Adding ${#INSTALL_DOMAINS[@]} domain(s) to database..."

        for domain in "${INSTALL_DOMAINS[@]}"; do
            mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" << EOSQL >> "${LOG_FILE}" 2>&1
INSERT INTO client_domains (domain, client_name, relay_host, active, created_at)
VALUES ('${domain}', '${domain}', '${RELAY_SERVER_IP}', 1, NOW())
ON DUPLICATE KEY UPDATE active = 1, relay_host = '${RELAY_SERVER_IP}';
EOSQL

            if [[ $? -eq 0 ]]; then
                success "Added domain: ${domain}"
            else
                warn "Failed to add domain: ${domain} (may need manual addition)"
            fi
        done
    else
        # Fallback to single domain
        info "Adding initial domain: ${INSTALL_DOMAIN}"

        mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" << EOSQL >> "${LOG_FILE}" 2>&1
INSERT INTO client_domains (domain, client_name, relay_host, active, created_at)
VALUES ('${INSTALL_DOMAIN}', '${INSTALL_DOMAIN}', '${RELAY_SERVER_IP}', 1, NOW())
ON DUPLICATE KEY UPDATE active = 1, relay_host = '${RELAY_SERVER_IP}';
EOSQL

        if [[ $? -eq 0 ]]; then
            success "Initial domain added"
        else
            warn "Failed to add initial domain (may need manual addition)"
        fi
    fi

    return 0  # Non-fatal
}

#
# Create SpacyWeb admin user
#
create_admin_user() {
    info "Creating SpacyWeb admin user: ${ADMIN_USER}"

    # Hash password using Python bcrypt
    local password_hash
    password_hash=$(/opt/spacyserver/venv/bin/python3 -c "import bcrypt; print(bcrypt.hashpw('${ADMIN_PASSWORD}'.encode(), bcrypt.gensalt()).decode())")

    if [[ $? -ne 0 ]]; then
        error "Failed to hash password"
        return 1
    fi

    # Use INSTALL_DOMAINS_LIST if available (multiple domains), otherwise INSTALL_DOMAIN
    local authorized_domains="${INSTALL_DOMAINS_LIST:-${INSTALL_DOMAIN}}"

    mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" << EOSQL >> "${LOG_FILE}" 2>&1
INSERT INTO users (email, password_hash, domain, authorized_domains, role, is_active, created_at)
VALUES ('${ADMIN_EMAIL}', '${password_hash}', '${INSTALL_DOMAIN}', '${authorized_domains}', 'admin', 1, NOW())
ON DUPLICATE KEY UPDATE
    password_hash = '${password_hash}',
    domain = '${INSTALL_DOMAIN}',
    authorized_domains = '${authorized_domains}',
    role = 'admin';
EOSQL

    if [[ $? -eq 0 ]]; then
        success "Admin user created"
        save_state "admin_user_created"
        return 0
    else
        error "Failed to create admin user"
        return 1
    fi
}

#
# Configure conversation learning system
#
configure_conversation_learning() {
    info "Configuring conversation learning system..."

    mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" << EOSQL >> "${LOG_FILE}" 2>&1
INSERT INTO conversation_learning_config (domain, enabled, learning_threshold, min_confidence, created_at)
VALUES ('${INSTALL_DOMAIN}', 1, 2.5, 0.70, NOW())
ON DUPLICATE KEY UPDATE enabled = 1;
EOSQL

    if [[ $? -eq 0 ]]; then
        success "Conversation learning configured"
        return 0
    else
        warn "Failed to configure conversation learning (non-fatal)"
        return 0
    fi
}

#
# Set up database tables for module tier
#
setup_module_tables() {
    info "Initializing module configuration for Tier ${MODULE_TIER}..."

    # This will be populated by the modules.sh setup
    success "Module tables ready"
    return 0
}

#
# Run all database setup steps
#
setup_database() {
    if is_step_completed "database_setup_complete"; then
        info "Database already configured, skipping..."
        return 0
    fi

    section "Database Setup"

    secure_mariadb || return 1
    create_database_and_user || return 1
    import_database_schema || return 1
    create_mysql_config || return 1
    insert_initial_domain || return 1
    create_admin_user || return 1
    configure_conversation_learning || return 1
    setup_module_tables || return 1

    save_state "database_setup_complete"
    success "Database setup complete"
    return 0
}

# Export functions
export -f secure_mariadb create_database_and_user import_database_schema
export -f create_mysql_config insert_initial_domain create_admin_user
export -f configure_conversation_learning setup_module_tables setup_database
