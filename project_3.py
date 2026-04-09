from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import rsa

def user_matrix():
    user_database = {}
    try:
        with open('user_matrix.txt', 'r') as file:
            for line in file:
                line = line.strip()
                if not line: continue                
                split_line = [s.strip() for s in line.split(',')]
                subject = split_line[0].split(':')
                if len(subject) < 2: continue
                username = subject[1].strip()
                user_attributes = {}
                for perms in split_line[1:]:
                    if ':' in perms:
                        file_name, file_perm = perms.split(':')
                        user_attributes[file_name.strip()] = file_perm.strip()
                user_database[username] = user_attributes
    except FileNotFoundError:
        print("Error. File not found.")
    return user_database

def rsa_key_file_creation():
    database = user_matrix()
    for username, attributes in database.items():
        (pubkey, privkey) = rsa.newkeys(1024)
        rsa_pub_b64 = base64.b64encode(pubkey.save_pkcs1()).decode('utf-8')
        rsa_priv_b64 = base64.b64encode(privkey.save_pkcs1()).decode('utf-8')
        user_attr_string = ", ".join([f"{key}: {value}" for key, value in attributes.items()])
        user_file = f"{username}_ca.txt"
        try:
            with open(user_file, 'w') as file:
                file.write(f"{rsa_pub_b64}\n")
                file.write(f"{rsa_priv_b64}\n")
                file.write(f"Attributes: {user_attr_string}\n")
            print(f"User Key File Created: {user_file}")
        except IOError as e:
            print(f"Error writing {user_file}: {e}")

def aes_key_file_creation():
    database = user_matrix()
    if not database:
        print("No user database found. Please run RSA Key Generation first.")
        return
    K = Random.new().read(32)
    print(f" Admin Generated Symmetric Key ".center(120, '-'))
    for name in database.keys():
            user_ca_file = f"{name}_ca.txt"
            share_file = f"{name}_sharekey.txt"
            try:
                with open(user_ca_file, 'r') as ca_file:
                    aes_pub_b64 = ca_file.readline().strip()
                aes_pub_pem = base64.b64decode(aes_pub_b64)
                aes_public_key = rsa.PublicKey.load_pkcs1(aes_pub_pem)
                encrypted_k = rsa.encrypt(K, aes_public_key)
                encoded_k = base64.b64encode(encrypted_k).decode('utf-8')
                with open(share_file, 'w') as file:
                    file.write(encoded_k)
                print(f"AES Encrypted Share Key for: {name}")
            except FileNotFoundError:
                print(f"{ca_file} not found. Generate RSA keys first.")
            except Exception as e:
                print(f"Failed to create Share key for {name}; {e}")
    print("-" * 120)
    return K

def file_encryption(K):
    abac_policy = "(attr1 AND attr2) OR (attr3 AND attr4 AND attr5)"
    aes_padding = 16
    try:
        with open('plaintext.txt', 'rb') as file:
            pt_file = file.read()
        
        iv = Random.new().read(aes_padding)

        aes_cipher = AES.new(K, AES.MODE_CBC, iv)

        aes_cipher_text = aes_cipher.encrypt(pad(pt_file, aes_padding))

        with open('plaintext.txt.enc', 'wb') as enc_file:
            enc_file.write(f"ABAC Policy: {abac_policy}\n".encode('utf-8'))
            enc_file.write(base64.b64encode(iv) + b"\n")
            enc_file.write(base64.b64encode(aes_cipher_text))

        print("Successfully encrypted file.")
        
    except FileNotFoundError:
        print(f"Error: 'plaintext.txt' not found.")
    except Exception as e:
        print(f"Encryption failed: {e}")

def file_decryption(K, username):
    database = user_matrix()
    if username not in database:
        print(f"User {username} not found.")
        return
    user_attributes = database[username]
    has_attr = lambda a: user_attributes.get(a) == 'x'
    condition1 = has_attr("attr1") and has_attr("attr2")
    condition2 = has_attr("attr3") and has_attr("attr4") and has_attr("attr5")

    if not (condition1 or condition2):
        print(" Access DENIED for: {username}".center(120, '!'))
        return
    print(" Access GRANTED for: {username}".center(120, '='))

    try: 
        with open('plaintext.txt.enc', 'rb') as enc_file:
            lines = enc_file.readlines()
            iv = base64.b64decode(lines[1].strip())
            ciphertext = base64.b64decode(lines[2].strip())
        aes_cipher = AES.new(K, AES.MODE_CBC, iv)
        decrypted_data = unpad(aes_cipher.decrypt(ciphertext), 16)

        with open('plaintext.txt', 'wb') as dec_file:
            dec_file.write(decrypted_data)
        print("Decrypted data has been written to 'plaintext.txt'.")
        print(f"Preview: {decrypted_data.decode('utf-8')[:30]}...")
        print("-" * 120)

    except FileNotFoundError:
        print("Error: 'plaintext.txt.enc' not found.")
    except Exception as e:
        print("Decryption or Write failed: {e}")
        
def admin_menu():
    persistent_k = None
    while True:
        print(" ADMIN SESSION ".center(120,'-')) 
        print("Please select an action:")
        print("1. RSA Key Generation.")
        print("2. AES Key Generation.")
        print("3. File Encryption.")
        print("4. View MAC File.")
        print("5. Check a user's file permissions.")        
        print("6. Log Out.")
        print("7. Exit")
        print("-" * 120)
        choice = input("Please enter 1, 2, 3, 4, 5, 6 or 7: ")
        match choice:
            case '1':
                rsa_key_file_creation()
            case '2':
                persistent_k = aes_key_file_creation()
            case '3':
                if persistent_k is not None:
                    file_encryption(persistent_k)
                else: 
                    print("Error No AES Key found, please run AES Key Generation (Option 2) First.")
            case '6':
                print("Signing Out.")
                break
            case '7':
                print("[TERMINATING SESSION]".center(120, '*'))
                exit()
            case _:
                print("Invalid selection. Please enter 1, 2, 3, 4, 5, 6 or 7.")


def main():
    while True:
        username_entry = input("Enter 'admin' for Admin Menu | Enter 'exit' to Exit: ").strip().lower()
        match username_entry:
            case 'admin':
                print('-' * 120)
                print(f" [ADMIN ACCESS GRANTED] ".center(120, '-'))
                admin_menu()
            case 'exit':
                print(f" [TERMINATING SESSION] ".center(120, "*"))
                exit()
            case _:
                print("Invalid entry. Please enter 'admin' or 'exit'")

main()

# # Assuming persistent_k is stored from Option 2
# target_user = input("Enter your username to attempt decryption: ").strip()

# # Pass the key and the name; the function handles the matrix lookup
# file_decryption(persistent_k, target_user)