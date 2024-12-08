import os
import sqlite3
import json
import hashlib
import secrets
import string
import logging
from datetime import datetime
from typing import Dict, List, Any

class PasswordVaultManager:
    def __init__(self, vault_name: str = 'default_vault'):
        """
        Inisialisasi Vault Password dengan manajemen yang lebih canggih
        
        Args:
            vault_name (str): Nama vault untuk identifikasi
        """
        # Konfigurasi direktori
        self.base_dir = os.path.join('password_vaults', vault_name)
        os.makedirs(self.base_dir, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Inisialisasi database
        self.db_path = os.path.join(self.base_dir, 'password_vault.db')
        self._init_database()
    
    def _setup_logging(self):
        """Konfigurasi logging yang lebih detail"""
        log_dir = os.path.join(self.base_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'vault_activity.log')),
                logging.StreamHandler()
            ]
        )
    
    def _init_database(self):
        """
        Inisialisasi struktur database yang komprehensif
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # tbel utama untuk password
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    complexity_score INTEGER,
                    strength_rating TEXT,
                    
                    -- Detail Karakter
                    total_length INTEGER,
                    uppercase_count INTEGER,
                    lowercase_count INTEGER,
                    digit_count INTEGER,
                    special_char_count INTEGER,
                    
                    -- Metadata
                    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_used_at DATETIME,
                    usage_count INTEGER DEFAULT 0,
                    
                    -- Tambahan
                    entropy REAL,
                    notes TEXT,
                    category TEXT
                )
                ''')
                
                # tabel riwayat penggunaan
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER,
                    action TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(password_id) REFERENCES passwords(id)
                )
                ''')
                
                conn.commit()
                logging.info("Database vault diinisialisasi berhasil")
        
        except sqlite3.Error as e:
            logging.error(f"Kesalahan inisialisasi database: {e}")
    
    def generate_passwords(
        self, 
        num_passwords: int = 5, 
        min_length: int = 12, 
        max_length: int = 24,
        complexity: str = 'balanced'
    ) -> List[Dict[str, Any]]:
        """
        menghasilkan password dengan analisis mendalam
        
        Returns:
            List dari dictionary password dengan detail lengkap
        """
        generated_passwords = []
        
        # Definisi kompleksitas
        complexity_config = {
            'low': {
                'uppercase_ratio': 0.1,
                'lowercase_ratio': 0.6,
                'digit_ratio': 0.2,
                'special_char_ratio': 0.1
            },
            'balanced': {
                'uppercase_ratio': 0.25,
                'lowercase_ratio': 0.25,
                'digit_ratio': 0.25,
                'special_char_ratio': 0.25
            },
            'high': {
                'uppercase_ratio': 0.3,
                'lowercase_ratio': 0.2,
                'digit_ratio': 0.3,
                'special_char_ratio': 0.2
            }
        }
        
        current_config = complexity_config.get(complexity, complexity_config['balanced'])
        
        for i in range(num_passwords):
            # menentuka panjang password
            length = secrets.randbelow(max_length - min_length + 1) + min_length
            
            # menghitung jumlah karakter
            uppercase_count = int(length * current_config['uppercase_ratio'])
            lowercase_count = int(length * current_config['lowercase_ratio'])
            digit_count = int(length * current_config['digit_ratio'])
            special_char_count = length - (uppercase_count + lowercase_count + digit_count)
            
            # membuat password
            password_chars = (
                [secrets.choice(string.ascii_uppercase) for _ in range(uppercase_count)] +
                [secrets.choice(string.ascii_lowercase) for _ in range(lowercase_count)] +
                [secrets.choice(string.digits) for _ in range(digit_count)] +
                [secrets.choice(string.punctuation) for _ in range(special_char_count)]
            )
            
            # mengacak urutan
            secrets.SystemRandom().shuffle(password_chars)
            password = ''.join(password_chars)
            
            # menganalisis password
            password_details = self._analyze_password(password)
            
            # menyimpan ke database
            password_id = self._save_password(
                name=f"Generated-{i+1}",
                password=password, 
                details=password_details
            )
            
            # output
            generated_passwords.append({
                'id': password_id,
                'name': f"Generated-{i+1}",
                'password': password,
                'details': password_details
            })
        
        return generated_passwords
    
    def _analyze_password(self, password: str) -> Dict[str, Any]:
        """
        Analisis password
        
        Returns:
            Dictionary dengsn detalil analisis
        """
        # Perhitungan karakter
        details = {
            'total_length': len(password),
            'uppercase_count': sum(1 for c in password if c.isupper()),
            'lowercase_count': sum(1 for c in password if c.islower()),
            'digit_count': sum(1 for c in password if c.isdigit()),
            'special_char_count': sum(1 for c in password if c in string.punctuation)
        }
        
        # Perhitungan entropi
        unique_chars = len(set(password))
        details['entropy'] = len(password) * (unique_chars / len(password)) ** 2
        
        # Skor kompleksitas
        complexity_score = sum([
            details['total_length'] >= 12,
            details['uppercase_count'] > 0,
            details['lowercase_count'] > 0,
            details['digit_count'] > 0,
            details['special_char_count'] > 0,
            details['entropy'] > 3.0
        ])
        
        # rating kekuatan
        if complexity_score <= 2:
            strength_rating = 'Lemah'
        elif complexity_score <= 4:
            strength_rating = 'Sedang'
        else:
            strength_rating = 'Kuat'
        
        details['complexity_score'] = complexity_score
        details['strength_rating'] = strength_rating
        
        return details
    
    def _save_password(self, name: str, password: str, details: Dict[str, Any]) -> int:
        """
        Simpan password ke database dengan enkripsi HASH
        
        Returns:
            ID password yang diisimpan
        """
        try:
            # Generate salt
            salt = secrets.token_hex(16)
            
            # Hash password dengan salt
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Simpan password
                cursor.execute('''
                INSERT INTO passwords (
                    name, password_hash, salt, 
                    complexity_score, strength_rating,
                    total_length, uppercase_count, 
                    lowercase_count, digit_count, 
                    special_char_count, entropy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    name, 
                    password_hash, 
                    salt,
                    details['complexity_score'], 
                    details['strength_rating'],
                    details['total_length'],
                    details['uppercase_count'],
                    details['lowercase_count'], 
                    details['digit_count'], 
                    details['special_char_count'],
                    details['entropy']
                ))
                
                password_id = cursor.lastrowid
                
                # Catat riwayat
                cursor.execute('''
                INSERT INTO password_history (password_id, action) 
                VALUES (?, ?)
                ''', (password_id, 'generated'))
                
                conn.commit()
                
                logging.info(f"Password {name} disimpan dengan ID {password_id}")
                
                return password_id
        
        except sqlite3.Error as e:
            logging.error(f"Kesalahan menyimpan password: {e}")
            return -1
    
    def export_vault(self, format: str = 'json'):
        """
        Ekspor seluruh vault kedalam format
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # mengambil semua password
                cursor.execute('SELECT * FROM passwords')
                passwords = cursor.fetchall()
                
                # menyiapkan direktori ekspor
                export_dir = os.path.join(self.base_dir, 'exports')
                os.makedirs(export_dir, exist_ok=True)
                
                # nama file timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                if format == 'json':
                    filepath = os.path.join(export_dir, f'vault_export_{timestamp}.json')
                    with open(filepath, 'w') as f:
                        json.dump(passwords, f, indent=4)
                
                elif format == 'csv':
                    import csv
                    filepath = os.path.join(export_dir, f'vault_export_{timestamp}.csv')
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            'ID', 'Nama', 'Hash Password', 'Salt', 'Skor Kompleksitas', 
                            'Rating Kekuatan', 'Panjang', 'Huruf Besar', 
                            'Huruf Kecil', 'Digit', 'Karakter Khusus', 
                            'Entropi', 'Waktu Dibuat'
                        ])
                        writer.writerows(passwords)
                
                logging.info(f"Vault diekspor ke {filepath}")
                return filepath
        
        except Exception as e:
            logging.error(f"Kesalahan ekspor vault: {e}")
            return None

def main():
    # contoh penggunaanya
    try:
        # buat vault baru
        vault = PasswordVaultManager(vault_name='personal_vault')
        
        # generate passwordsnya
        generated_passwords = vault.generate_passwords(
            num_passwords=5,
            complexity='balanced'
        )
        
        # menampilkan detailnya
        print("\n📋 Detail Password Yang Dihasilkan:")
        for pwd in generated_passwords:
            print(f"\nPassword ID: {pwd['id']}")
            print(f"Nama: {pwd['name']}")
            print(f"Password: {pwd['password']}")
            print("Analisis:")
            for key, value in pwd['details'].items():
                print(f"- {key.replace('_', ' ').title()}: {value}")
        
        # ekspor vault
        export_path = vault.export_vault(format='json')
        print(f"\n💾 Vault diekspor ke: {export_path}")
    
    except Exception as e:
        logging.error(f"Kesalahan utama: {e}")

if __name__ == "__main__":
    main()