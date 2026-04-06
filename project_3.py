def permission_matrix(macfile):
    user_database = {}
    try:
        with open(macfile, 'r') as file:
            for line in file:
                line = line.strip()
                if not line: continue                
                split_line = [s.strip() for s in line.split(',')]
                subject = split_line[0].split(':')
                if len(subject) < 2: continue
                username = subject[1].strip()
                user_permissions = {}
                for perms in split_line[1:]:
                    if ':' in perms:
                        file_name, file_perm = perms.split(':')
                        user_permissions[file_name.strip()] = file_perm.strip()
                user_database[username] = user_permissions
    except FileNotFoundError:
        print("Error. File not found.")
    return user_database