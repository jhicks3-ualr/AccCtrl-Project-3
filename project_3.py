from Crypto import Random                   # These are all of the imports used, Crypto from the pyCryptodome Library
from Crypto.Cipher import AES               # for AES encryption
from Crypto.Util.Padding import pad, unpad  # for AES padding and unpadding
import base64                               # the base64 for encoding and decoding
import rsa                                  # the rsa for RSA encryption
from pathlib import Path                    # imported for file path handling
import bcrypt                               # imported for bcrypt salting of passwords
import os                                   # imported for file creation and deletion

#this function reads the user_matrix.txt file and then uses the information in the file to create a dictionary of the user's and their attributes
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

#this function simply reads the user_matrix.txt file and prints the information
def view_database():
    print(" [USER DATABASE] ".center(100, '-'))
    try:
        with open('user_matrix.txt', 'r') as file:
            for line in file:
                if line.strip():
                    print(line.strip())
    except FileNotFoundError:
        print("Database file not found.")
    print('-' * 100)
    pause()

#this function adds a new user to the user_matrix.txt file by reading the file storing the information, appending it with the new user
#and writing all of the information back to the file to prevent any white space or incorrect formatting
#then the new user has their RSA encryption keys created and their share key created using the previously created Symmetric Key
def add_new_user(current_k):
    print(" ADDING NEW USER ".center(100,'-'))
    while True:
        input_new_user = input("Please enter a new Username or type 'cancel' to return to the previous menu:\n").strip()
        match input_new_user:
            case 'cancel':
                return
            case _:
                break
    print("Attribute options: x = has attribute | o = does not have attribute.")
    attr_options = ['x', 'o']
    attributes = []
    attr_dict = {}
    for i in range(1,6):
        while True:
            attr = input(f"Enter selection for Attribute {i} (i.e. 'x' or 'o'): ")
            match attr:
                case _ if attr in attr_options:
                    attributes.append(f"attr{i}: {attr}")
                    attr_dict[f"attr{i}"] = attr
                    break
                case _:
                    print("Invalid entry: Please enter 'x' or 'o': ")
    new_line_entry = f"subject: {input_new_user}, " + ", ".join(attributes) + "\n"
    with open('user_matrix.txt', 'r') as file:
        lines = [line for line in file if line.strip()]
    lines.append(new_line_entry)
    with open('user_matrix.txt', 'w') as file:
        file.writelines(lines)
    print("-" * 100)
    rsa_folder = Path("RSA_Keys")
    rsa_folder.mkdir(parents=True, exist_ok=True)
    rsa_file_path = rsa_folder / f"{input_new_user}_ca.txt"
    (pubkey, privkey) = rsa.newkeys(1024)    #these lines create the RSA public key for encryption and the private for decryption, the 1024 value is the bit length of the keys
    rsa_pub_b64 = base64.b64encode(pubkey.save_pkcs1()).decode('utf-8') #this turns the binary of the pub key into a standard text format so it can be stored in a file
    rsa_priv_b64 = base64.b64encode(privkey.save_pkcs1()).decode('utf-8') #this turns the binary of the priv key into a standard text format so it can be stored in a file
    attr_string = ", ".join([f"{k}: {v}" for k, v in attr_dict.items()])
    with rsa_file_path.open('w') as rsa_file:
        rsa_file.write(f"{rsa_pub_b64}\n")
        rsa_file.write(f"{rsa_priv_b64}\n")
        rsa_file.write(f"Attributes: {attr_string}\n")
    if current_k:
        share_folder = Path("Share_Keys")
        share_folder.mkdir(parents=True, exist_ok=True)
        share_file_path = share_folder / f"{input_new_user}_sharekey.txt"
        encrypted_k = rsa.encrypt(current_k, pubkey) #uses the previously generated Symmetric key and the users new public key for the Share Key creation
        encoded_k = base64.b64encode(encrypted_k).decode('utf-8') #this turns the binary of the share key into a standard text format so it can be stored in a file
        with share_file_path.open('w') as s_file:
            s_file.write(encoded_k)
    else:
        print("No Active AES Key Found. Share key not generated.")
    print(f"User {input_new_user} as been added to the Database, and their RSA Key and Share Key files have been created.")
    print("-" * 100)
    pause()

#this function simply edits a users attributes and writes the new attributes back to the user_matrix.txt file
#and then updates the attributes saved in the corresponding RSA Key File
def edit_user_attributes():
    print(" EDITING USER PERMISSIONS ".center(100,'-'))
    database = user_matrix()
    print("Attribute options: x = has attribute | o = does not have attribute.")
    attr_options = ['x', 'o']
    attributes = []
    attr_dict = {}
    rsa_folder = Path("RSA_Keys")
    rsa_folder.mkdir(parents=True, exist_ok=True)
    while True:
        selected_user = input("Please enter a Username or type 'cancel' to return to the Admin Menu:\n").strip()
        match selected_user:
            case 'cancel':
                return
            case _ if selected_user in database:
                break
            case _:
                print(f"{selected_user} not found in User Database.")
    for i in range(1,6):
        while True:
            new_attr = input(f"Enter selection for Attribute {i} (i.e. 'x' or 'o'): ").strip().lower()
            match new_attr:
                case _ if new_attr in attr_options:
                    attributes.append(f"attr{i}: {new_attr}")
                    attr_dict[f"attr{i}"] = new_attr
                    break
                case _:
                    print("Invalid entry: Please enter 'x' or 'o': ")
    new_attr_line = f"subject: {selected_user}, " + ", ".join(attributes) + "\n"
    try:
        with open ('user_matrix.txt', 'r') as file:
            lines = file.readlines()
        updated_file_line = []
        user_found = False
        for line in lines:
            if line.startswith(f"subject: {selected_user},"):
                updated_file_line.append(new_attr_line)
                user_found = True
            else:
                updated_file_line.append(line)
        if user_found:
            with open ('user_matrix.txt', 'w') as file:
                file.writelines(updated_file_line)
            rsa_path = Path("RSA_Keys") / f"{selected_user}_ca.txt"
            if rsa_path.exists():
                with open(rsa_path, 'r') as file:
                    lines = file.readlines()
                pub_key = lines[0].strip()
                priv_key = lines[1].strip()
                updated_ca_file_line = ", ".join([f"{k}: {v}" for k, v in attr_dict.items()])
                with open(rsa_path, 'w') as ca_file:
                    ca_file.write(f"{pub_key}\n")
                    ca_file.write(f"{priv_key}\n")
                    ca_file.write(f"Attributes: {updated_ca_file_line}\n")
            else:
                print(f"RSA File for {selected_user} does not exist.")
    except Exception as e:
        print(f"There was an error writing {e}.")
        print("-" * 100)
    print("-" * 100)
    print(f"User Database and RSA Key File for {selected_user} have been updated with the users new permissions.")
    print("-" * 100)
    pause()

#this function creates all of the users in the user_matrix.txt public and private RSA keys and saves them to their corresponding RSA Key File.
def rsa_key_file_creation():
    database = user_matrix()
    rsa_folder = Path("RSA_Keys")
    rsa_folder.mkdir(parents=True, exist_ok=True)
    print(f" [RSA KEY FILE CREATION] ".center(100, '-'))
    for username, attributes in database.items():
        (pubkey, privkey) = rsa.newkeys(1024) #this line creats the Public and Private RSA keys with a length of 1024 bites
        rsa_pub_b64 = base64.b64encode(pubkey.save_pkcs1()).decode('utf-8') #this turns the binary of the pub key into a standard text format so it can be stored in a file
        rsa_priv_b64 = base64.b64encode(privkey.save_pkcs1()).decode('utf-8') #this turns the binary of the private key into a standard text format so it can be stored in a file
        user_attr_string = ", ".join([f"{key}: {value}" for key, value in attributes.items()])
        user_file = f"{username}_ca.txt"
        rsa_file_path = rsa_folder / user_file
        try:
            with rsa_file_path.open('w') as file:
                file.write(f"{rsa_pub_b64}\n")
                file.write(f"{rsa_priv_b64}\n")
                file.write(f"Attributes: {user_attr_string}\n")
            print(f"RSA Key File {user_file} has been created.")
        except IOError as e:
            print(f"Error writing {user_file}: {e}")
    print("-" * 100)        
    pause()

#this function creates the Symmetric Key (K) and uses the corresponding user's RSA Public Key to Create and AES Share Key File
#it then returns the K variable for use in other functions to maintain integrity.
def aes_key_file_creation():
    database = user_matrix()
    if not database:
        print("No user database found. Please run RSA Key Generation first.")
        return
    K = Random.new().read(32) #this creates the 256 (32 x 8 = 256) bit Symmetric Key
    print(f" [SHARE KEY FILE CREATION] ".center(100, '-'))
    rsa_folder = Path("RSA_Keys")
    share_folder = Path("Share_Keys")
    share_folder.mkdir(parents=True, exist_ok=True)
    for name in database.keys():
            user_ca_file = f"{name}_ca.txt"
            share_file = f"{name}_sharekey.txt"
            rsa_file_path = rsa_folder / user_ca_file
            share_file_path = share_folder / share_file
            try:
                with rsa_file_path.open('r') as ca_file:
                    aes_pub_b64 = ca_file.readline().strip()
                if not aes_pub_b64:
                    print(f"Public key for {name} is empty.")
                aes_pub_pem = base64.b64decode(aes_pub_b64) #decodes the RSA public key
                aes_public_key = rsa.PublicKey.load_pkcs1(aes_pub_pem) # unencrypts and loads the RSA public key for use
                encrypted_k = rsa.encrypt(K, aes_public_key) #encrypts a new Share key using the decoded RSA Key and Symmetric Key
                encoded_k = base64.b64encode(encrypted_k).decode('utf-8') #encodes the binary of the newly created and encrypted Share Key
                with share_file_path.open('w') as file:
                    file.write(encoded_k)
                print(f"AES Encrypted Share Key file for {name} has been created.")
            except FileNotFoundError:
                print(f"{rsa_file_path} not found. Generate RSA keys first.")
            except Exception as e:
                print(f"Failed to create Share key for {name}; {e}")
    print("-" * 100)
    pause()
    return K

#this function uses the Symmetric Key to encrypt the plaintext.txt file and name it plaintext.txt.enc
def file_encryption(K):
    abac_policy = "(attr1 AND attr2) OR (attr3 AND attr4 AND attr5)"
    aes_padding = 16 #adds filler bytes to the file to make it a multiple of 16
    input_file = 'plaintext.txt'
    output_file = 'plaintext.txt.enc'
    try:
        with open(input_file, 'rb') as file:
            pt_file = file.read()
        iv = Random.new().read(aes_padding) #creates an initialization vector with the aes_padding variable for security
        aes_cipher = AES.new(K, AES.MODE_CBC, iv) #creates the AES Cipher using the symmetric key in Cipher Block Chaining with the initialization vector
        aes_cipher_text = aes_cipher.encrypt(pad(pt_file, aes_padding)) #this pads the file text and then encrypts it with aes_cipher
        with open(output_file, 'wb') as enc_file:
            enc_file.write(base64.b64encode(iv) + b"\n") #this encodes the binary of the IV to the second line of the file
            enc_file.write(base64.b64encode(aes_cipher_text)) #this encodes the binary of the encrypted text to the file's 3rd line
        os.remove(input_file) #deletes the unencrypted file.
        print(f" [FILE ENCRYPTION] ".center(100, '-'))
        print("Successfully encrypted 'plaintext.txt'.") 
        print("-" * 100)
    except FileNotFoundError:
        print(f"Error: 'plaintext.txt' not found.")
    except Exception as e:
        print(f"Encryption failed: {e}")
    pause()

#this is the file decryption function that uses the Symmetric key, share key, private key, and User Attributes to decrypt and display
#the unencrypted file text
#first the users attributes are checked for authorization, if the user has the correct attributes
#the file attempts to be decoded with the users private key
def file_decryption(K, username):
    database = user_matrix()
    input_file = 'plaintext.txt.enc'
    output_file = 'plaintext.txt'
    if username not in database:
        print(f"User {username} not found.")
        return
    user_attributes = database[username]
    has_attr = lambda a: user_attributes.get(a) == 'x' #this line creats a boolean comparison for user attributes using 'x' as the True value.
    condition1 = has_attr("attr1") and has_attr("attr2") #first part of the Attribute control policy
    condition2 = has_attr("attr3") and has_attr("attr4") and has_attr("attr5") #second part of the Attribute control policy
    if not (condition1 or condition2):
        print(f" Access DENIED for: {username} ".center(100, '!'))
        return
    print(f" Access GRANTED for: {username} ".center(100, '='))
    try: 
        with open(input_file, 'rb') as enc_file:
            lines = enc_file.readlines()
            iv = base64.b64decode(lines[0].strip()) #decodes 2nd line of plaintext file into 16 bit binary
            ciphertext = base64.b64decode(lines[1].strip()) #decodes 3rd line from Base64 back into raw ciphertext
        aes_cipher = AES.new(K, AES.MODE_CBC, iv) #reverses cipher from previous file_encryption function
        decrypted_data = unpad(aes_cipher.decrypt(ciphertext), 16) #removes padding from previous file_encryption function
        with open(output_file, 'wb') as dec_file:
            dec_file.write(decrypted_data)#writes the decrypted data to a temporary file that is then deleted after viewing, so that it does not require re-encryption
        print("You have successfully decrypted 'plaintext.txt.enc'.")
        print(f"Preview: {decrypted_data.decode('utf-8')[:75]}...")
        print("-" * 100)
        pause()
        if os.path.exists(output_file):
            os.remove(output_file)
            print(f" [Exiting: File has been re-encrypted.] ".center(100, '-'))
            print('*' * 100)
    except FileNotFoundError:
        print("Error: 'plaintext.txt.enc' not found.")
    except Exception as e:
        print(f"Decryption or Write failed: {e}")
    pause()

#this is the admin menu that requires the admin sign in to access
#it allows the admin to generate the RSA Keys, Share Keys, Symmetric Key, encrypt the 'plaintext.txt' file
#edit user attributes, add new users and view the existing user database.       
def admin_menu(current_k):
    persistent_k = current_k
    while True:
        print(" [ADMIN SESSION] ".center(100,'-')) 
        print("Please select an action:")
        print("1. RSA Key Generation.")
        print("2. Share Key Generation.")
        print("3. Encrypt File.")
        print("4. Create and Encrypt New User.")
        print("5. Edit Existing User Attributes.")
        print("6. View User Database.")        
        print("7. Log Out.")
        print("8. Exit")
        print("-" * 100)
        choice = input("Please enter 1, 2, 3, 4, 5, 6, 7, or 8: ")
        match choice:
            case '1':
                rsa_key_file_creation()
            case '2':
                persistent_k = aes_key_file_creation()
            case '3':
                if persistent_k:
                    file_encryption(persistent_k)
                else: 
                    print("Error No AES Key found, please run AES Key Generation (Option 2) First.")
            case '4':
                add_new_user(persistent_k)
            case '5':
                edit_user_attributes()
            case '6':
                view_database()
            case '7':
                print(f" [LOGGING OUT...] ".center(100, '-'))
                return persistent_k
            case '8':
                print(" [TERMINATING SESSION] ".center(100, '*'))
                exit()
            case _:
                print("Invalid selection. Please enter 1, 2, 3, 4, 5, 6, 7, or 8.")

#this is the user menu that is required for file decryption, the only function it provides is viewing the 
#unencrypted file content
def user_menu(username, K):
    while True:
        print(f" [USER SESSION: {username}] ".center(100,'-')) 
        print("Please select an action:")
        print("1. View File Content.")
        print("2. Log Out.")
        print("3. Exit")
        print("-" * 100)
        choice = input("Please enter 1, 2, or 3: ")
        match choice:
            case '1':
                if K is not None:
                    with open(f'RSA_Keys/{username}_ca.txt', 'r') as file:
                              lines = file.readlines()
                              priv_key_data = base64.b64decode(lines[1])#finds and decodes the users private key
                              private_key = rsa.PrivateKey.load_pkcs1(priv_key_data)#uses the private key 'unlock' the public key
                    with open(f'Share_Keys/{username}_sharekey.txt', 'r') as file:
                        encrypted_share_key = base64.b64decode(file.read()) #decodes the sharekey into bytes
                        try:
                            decrypted_share_key = rsa.decrypt(encrypted_share_key, private_key) #decrypts the Symmetric Key
                            file_decryption(decrypted_share_key, username) #calls the file_decryption function using the Unencrypted Symmetric Key and username
                        except rsa.DecryptionError:
                            print("RSA Key does not match, decryption failed.")
                        except FileNotFoundError:
                            print(f"Missing RSA and Share Key files for {username}") 
                        except Exception as e:
                            print(f"An error has occured: {e}")
                else:
                    print("Error No AES Key found, please run AES Key Generation first.")
            case '2':
                print("Signing Out...")
                break
            case '3':
                print("[TERMINATING SESSION]".center(100, '*'))
                exit()
            case _:
                print("!!Invalid Entry!! Please enter 1, 2, or 3: ")

#simple pause function to allow the user time to read the screen
def pause():
    input("Press Enter to Continue...")

#main function for Admin and User sign in, password is required for access and has a max of 3 attempts each
def main():
    K = None
    max_attempts = 3
    while True:
        admin_pw = "root".encode('utf-8')
        user_pw = "password".encode('utf-8')
        salt = bcrypt.gensalt(rounds = 12) #this hashes the password 2^12 times
        hashed_admin = bcrypt.hashpw(admin_pw, salt) #this hashes the admin password with the salt variable
        hashed_user = bcrypt.hashpw(user_pw, salt) #this hashes the user password with the salt variable
        database = user_matrix()
        username_entry = input("Enter 'admin' for Admin Menu | Enter a valid Username for the Standard User Menu | Enter 'q' to Quit:\n").strip()
        match username_entry:
            case 'admin':
                for attempt in range(max_attempts):
                    entered_admin_pw = input(f"Admin Password:\n").strip().encode('utf-8')
                    if bcrypt.checkpw(entered_admin_pw, hashed_admin):
                        print(f" [ADMIN ACCESS GRANTED] ".center(100, '*'))
                        K = admin_menu(K)
                        break
                    else:
                        remaining = max_attempts - (attempt + 1)
                        if remaining > 0:
                            print(f"Incorrect Password. {remaining} attempts remaining.")
                        else:
                            print("Too many failed attempts. Returning to Main Menu.")
            case _ if username_entry in database:
                for attempt in range(max_attempts):
                    entered_user_pw = input(f"Please enter your password:\n").strip().encode('utf-8')
                    if bcrypt.checkpw(entered_user_pw, hashed_user):
                        print(f" [USER ACCESS GRANTED: {username_entry}] ".center(100, '*'))
                        print('-' * 100)                
                        user_menu(username_entry, K)
                        break
                    else:
                        remaining = max_attempts - (attempt + 1)
                        if remaining > 0:
                            print(f"Incorrect Password. {remaining} attempts remaining.")
                        else:
                            print("Too many failed attempts. Returning to Main Menu.")
            case 'q':
                print(f" [TERMINATING SESSION] ".center(100, "*"))
                exit()
            case _:
                print("Invalid entry. Please enter 'admin' or 'exit'")

#calling of main function
main()

