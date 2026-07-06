-- Seed roles
INSERT INTO role (role_id, role_name, description)
VALUES ('ROL001', 'Administrator', 'System administrator with full access')
ON CONFLICT (role_id) DO NOTHING;

INSERT INTO role (role_id, role_name, description)
VALUES ('ROL002', 'Viewer', 'Standard user with limited access')
ON CONFLICT (role_id) DO NOTHING;

INSERT INTO role (role_id, role_name, description)
VALUES ('ROL003', 'Staff', 'Staff user with standard privileges')
ON CONFLICT (role_id) DO NOTHING;

INSERT INTO role (role_id, role_name, description)
VALUES ('ROL004', 'Security Analyst', 'Security analyst with elevated audit privileges')
ON CONFLICT (role_id) DO NOTHING;

-- Seed users with bcrypt-hashed passwords
INSERT INTO "user" (user_id, first_name, last_name, email, password, role_id, status, created_at)
VALUES ('USR001', 'Admin', 'User', 'admin@example.com', '$2b$12$HKNel9eMWG5bo4rwK0jEU.z.jiDIsSiVxkd6QltXz5aGT0RdxcINq', 'ROL001', 'Active', NOW())
ON CONFLICT (user_id) DO UPDATE SET
    first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name,
    email = EXCLUDED.email,
    password = EXCLUDED.password,
    role_id = EXCLUDED.role_id,
    status = EXCLUDED.status;

INSERT INTO "user" (user_id, first_name, last_name, email, password, role_id, status, created_at)
VALUES ('USR002', 'Sec', 'Analyst', 'analyst@example.com', '$2b$12$ozaoGLntrjsq.HdSbBw3a.xJ5Fd/YAQ4HiOv4DaU3nqzPDL2t6B7q', 'ROL004', 'Active', NOW())
ON CONFLICT (user_id) DO UPDATE SET
    first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name,
    email = EXCLUDED.email,
    password = EXCLUDED.password,
    role_id = EXCLUDED.role_id,
    status = EXCLUDED.status;
