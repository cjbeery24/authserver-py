-- This script sets up extensions and functions for the application database
-- PostgreSQL automatically creates the database and user based on:
-- POSTGRES_DB (from DATABASE_NAME), POSTGRES_USER (from DATABASE_USER), 
-- and POSTGRES_PASSWORD (from DATABASE_PASSWORD) environment variables

-- Enable UUID extension for generating unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto extension for cryptographic functions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone to UTC
SET timezone = 'UTC';

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';
