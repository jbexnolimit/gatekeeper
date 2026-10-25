INSERT INTO permissions (key, description)
VALUES
    ('roles.assign', 'Assign roles to users'),
    ('permissions.assign', 'Assign permissions to roles')
ON CONFLICT (key) DO NOTHING;
