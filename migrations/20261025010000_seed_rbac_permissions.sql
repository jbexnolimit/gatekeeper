INSERT INTO permissions (key, description)
VALUES
    ('roles.read', 'View roles'),
    ('roles.create', 'Create roles'),
    ('permissions.read', 'View permissions'),
    ('permissions.create', 'Create permissions')
ON CONFLICT (key) DO NOTHING;
