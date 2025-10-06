#!/usr/bin/env python3
"""
Steganografický nástroj - Program pre ukrývanie súborov do obrázkov
Implementuje LSB steganografiu s hlavičkou obsahujúcou metadáta o uloženom súbore.

Autor: [Pavol Comorek]
Dátum: 2025-10-05
"""

import os
import struct
from PIL import Image
import numpy as np
from typing import Optional, Tuple, List


class SteganographyTool:
    """Trieda pre steganografické operácie - ukrývanie a získavanie súborov z obrázkov."""
    
    def __init__(self):
        """Inicializácia steganografického nástroja."""
        self.HEADER_SIZE_BITS = 1 + 3 + (64 * 8) + 32 + 32  # spolu 580 bitov
        self.MAX_FILENAME_LENGTH = 64
        
    def _text_to_bits(self, text: str) -> str:
        """Prevedie text na binárny reťazec."""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def _bits_to_text(self, bits: str) -> str:
        """Prevedie binárny reťazec na text."""
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)
    
    def _file_to_bits(self, filepath: str) -> str:
        """Načíta súbor a prevedie na binárny reťazec."""
        with open(filepath, 'rb') as file:
            file_data = file.read()
        return ''.join(format(byte, '08b') for byte in file_data)
    
    def _bits_to_file(self, bits: str, output_path: str):
        """Prevedie binárny reťazec na súbor."""
        # Zaistíme, že počet bitov je násobok 8
        while len(bits) % 8 != 0:
            bits += '0'
            
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i+8]
            bytes_data.append(int(byte, 2))
        
        with open(output_path, 'wb') as file:
            file.write(bytes_data)
    
    def _get_pixel_positions(self, width: int, height: int, storage_method: int) -> List[Tuple[int, int]]:
        """Získa pozície pixelov podľa spôsobu uloženia."""
        positions = []
        
        if storage_method == 0:  # Každý pixel
            for y in range(height):
                for x in range(width):
                    positions.append((x, y))
                    
        elif storage_method == 1:  # Každý párny pixel (párna pozícia v sekvencii)
            count = 0
            for y in range(height):
                for x in range(width):
                    if count % 2 == 0:
                        positions.append((x, y))
                    count += 1
                    
        elif storage_method == 2:  # Každý nepárny pixel (nepárna pozícia v sekvencii)
            count = 0
            for y in range(height):
                for x in range(width):
                    if count % 2 == 1:
                        positions.append((x, y))
                    count += 1
                    
        elif storage_method == 3:  # Okraje obrázka
            # Horný a dolný okraj
            for x in range(width):
                positions.append((x, 0))  # horný okraj
                if height > 1:
                    positions.append((x, height - 1))  # dolný okraj
            
            # Ľavý a pravý okraj (bez rohov, ktoré sú už zahrnuté)
            for y in range(1, height - 1):
                positions.append((0, y))  # ľavý okraj
                if width > 1:
                    positions.append((width - 1, y))  # pravý okraj
        
        return positions
    
    def _embed_bits_in_image(self, image: Image.Image, bits: str, storage_method: int) -> Image.Image:
        """Vloží bity do obrázka podľa zvoleného spôsobu."""
        img_array = np.array(image)
        height, width = img_array.shape[:2]
        
        # Získame pozície pixelov podľa metódy ukrývania
        positions = self._get_pixel_positions(width, height, storage_method)
        
        # Kontrola, či máme dostatok pixelov
        if len(positions) * 3 < len(bits):  # 3 kanály RGB
            raise ValueError(f"Obrázok nemá dostatok pixelov pre uloženie dát. Potreba: {len(bits)} bitov, dostupné: {len(positions) * 3}")
        
        bit_index = 0
        for pos_x, pos_y in positions:
            if bit_index >= len(bits):
                break
                
            # Úprava RGB kanálov (LSB)
            for channel in range(3):  # RGB
                if bit_index < len(bits):
                    # Zmena LSB
                    img_array[pos_y, pos_x, channel] = (img_array[pos_y, pos_x, channel] & 0xFE) | int(bits[bit_index])
                    bit_index += 1
        
        return Image.fromarray(img_array)
    
    def _extract_bits_from_image(self, image: Image.Image, storage_method: int, start_bit: int, end_bit: int) -> str:
        """Extrahuje bity z obrázka podľa spôsobu uloženia."""
        img_array = np.array(image)
        height, width = img_array.shape[:2]
        
        positions = self._get_pixel_positions(width, height, storage_method)
        
        extracted_bits = []
        bit_index = 0
        
        for pos_x, pos_y in positions:
            for channel in range(3):  # RGB
                if start_bit <= bit_index <= end_bit:
                    # Získanie LSB
                    bit = img_array[pos_y, pos_x, channel] & 1
                    extracted_bits.append(str(bit))
                
                bit_index += 1
                if bit_index > end_bit:
                    break
            if bit_index > end_bit:
                break
        
        return ''.join(extracted_bits)
    
    def _create_header(self, is_file: bool, storage_method: int, filename: str, start_pos: int, end_pos: int) -> str:
        """Vytvorí hlavičku s metadátami."""
        header = []
        
        # 1. Typ (1 bit): 1 = súbor, 0 = text
        header.append('1' if is_file else '0')
        
        # 2. Spôsob uloženia (3 bity)
        header.append(format(storage_method, '03b'))
        
        # 3. Názov súboru (64 * 8 bitov)
        filename_padded = filename[:self.MAX_FILENAME_LENGTH].ljust(self.MAX_FILENAME_LENGTH, '\0')
        header.append(self._text_to_bits(filename_padded))
        
        # 4. Pozícia prvého bitu (32 bitov)
        header.append(format(start_pos, '032b'))
        
        # 5. Pozícia posledného bitu (32 bitov)
        header.append(format(end_pos, '032b'))
        
        return ''.join(header)
    
    def _parse_header(self, header_bits: str) -> dict:
        """Parsuje hlavičku a vráti metadáta."""
        if len(header_bits) < self.HEADER_SIZE_BITS:
            raise ValueError("Neplatná hlavička - príliš krátka")
        
        offset = 0
        
        # Typ
        is_file = header_bits[offset] == '1'
        offset += 1
        
        # Spôsob uloženia
        storage_method = int(header_bits[offset:offset+3], 2)
        offset += 3
        
        # Názov súboru
        filename_bits = header_bits[offset:offset+(64*8)]
        filename = self._bits_to_text(filename_bits).rstrip('\0')
        offset += 64 * 8
        
        # Pozícia prvého bitu
        start_pos = int(header_bits[offset:offset+32], 2)
        offset += 32
        
        # Pozícia posledného bitu
        end_pos = int(header_bits[offset:offset+32], 2)
        
        return {
            'is_file': is_file,
            'storage_method': storage_method,
            'filename': filename,
            'start_pos': start_pos,
            'end_pos': end_pos
        }
    
    def hide_file(self, image_path: str, file_path: str, output_path: str, storage_method: int = 0) -> bool:
        """
        Ukryje súbor do obrázka.
        
        Args:
            image_path: Cesta k pôvodnému obrázku
            file_path: Cesta k súboru na ukrytie
            output_path: Cesta k výstupnému obrázku
            storage_method: Spôsob ukrývania (0-3)
        
        Returns:
            bool: True pri úspechu
        """
        try:
            # Načítanie obrázka
            image = Image.open(image_path).convert('RGB')
            
            # Načítanie súboru
            filename = os.path.basename(file_path)
            file_bits = self._file_to_bits(file_path)
            
            # Výpočet pozícii
            start_pos = self.HEADER_SIZE_BITS
            end_pos = start_pos + len(file_bits) - 1
            
            # Vytvorenie hlavičky
            header = self._create_header(True, storage_method, filename, start_pos, end_pos)
            
            # Spojenie hlavičky a dát
            all_bits = header + file_bits
            
            # Vloženie do obrázka
            stego_image = self._embed_bits_in_image(image, all_bits, storage_method)
            
            # Uloženie
            stego_image.save(output_path, 'PNG')
            
            print(f"Súbor '{filename}' bol úspešne ukrytý do obrázka '{output_path}'")
            print(f"Použitá metóda: {storage_method}")
            print(f"Veľkosť dát: {len(file_bits)} bitov")
            
            return True
            
        except Exception as e:
            print(f"Chyba pri ukrývaní súboru: {e}")
            return False
    
    def hide_text(self, image_path: str, text: str, output_path: str, storage_method: int = 0) -> bool:
        try:
            # Načítanie obrázka
            image = Image.open(image_path).convert('RGB')
            img_array = np.array(image)
            height, width = img_array.shape[:2]
            
            # Konverzia textu na bity
            text_bits = self._text_to_bits(text)
            
            # Výpočet pozícii
            start_pos = self.HEADER_SIZE_BITS
            end_pos = start_pos + len(text_bits) - 1
            
            # Vytvorenie hlavičky (is_file = False pre text)
            header = self._create_header(False, storage_method, "user_text.txt", start_pos, end_pos)
            
            # Kontrola kapacity obrázka
            total_bits = len(header) + len(text_bits)
            positions = self._get_pixel_positions(width, height, storage_method)
            available_bits = len(positions) * 3  # 3 kanály RGB
            
            if total_bits > available_bits:
                print(f"\n❌ CHYBA: Text je príliš dlhý!")
                print(f"Požadované bity: {total_bits}")
                print(f"Dostupné bity: {available_bits}")
                print(f"Maximálna dĺžka textu: {(available_bits - len(header)) // 8} znakov")
                return False
            
            print(f"\n✅ KONTROLA KAPACITY PREŠLA:")
            print(f"Text: {len(text)} znakov ({len(text_bits)} bitov)")
            print(f"Hlavička: {len(header)} bitov")
            print(f"Celkom: {total_bits} bitov")
            print(f"Dostupné: {available_bits} bitov")
            print(f"Využitie: {(total_bits/available_bits)*100:.1f}%")
            
            # Spojenie hlavičky a dát
            all_bits = header + text_bits
            
            # Vloženie do obrázka
            stego_image = self._embed_bits_in_image(image, all_bits, storage_method)
            
            # Uloženie
            stego_image.save(output_path, 'PNG')
            
            print(f"\nText bol úspešne ukrytý do obrázka '{output_path}'")
            print(f"Použitá metóda: {storage_method}")
            
            return True
            
        except Exception as e:
            print(f"Chyba pri ukrývaní textu: {e}")
            return False
    
    def extract_file(self, stego_image_path: str, output_dir: str = ".") -> bool:
        try:
            # Načítanie obrázka
            image = Image.open(stego_image_path).convert('RGB')
            header_bits = None
            used_method = None
            
            for test_method in range(4):
                try:
                    test_header = self._extract_bits_from_image(image, test_method, 0, self.HEADER_SIZE_BITS - 1)
                    # Skúsime parsovať hlavičku
                    test_metadata = self._parse_header(test_header)
                    # Ak parsovanie prebehlo bez chyby a metóda sa zhoduje
                    if test_metadata['storage_method'] == test_method:
                        header_bits = test_header
                        used_method = test_method
                        break
                except:
                    continue
            
            if header_bits is None:
                raise ValueError("Nie je možné nájsť platnú hlavičku")
            
            # Parsovanie hlavičky
            metadata = self._parse_header(header_bits)
            # Použijeme zistenú metódu namiesto tej z hlavičky
            metadata['storage_method'] = used_method
            
            print(f"Nájdené metadáta:")
            print(f"  Typ: {'Súbor' if metadata['is_file'] else 'Text'}")
            print(f"  Metóda uloženia: {metadata['storage_method']}")
            print(f"  Názov súboru: {metadata['filename']}")
            print(f"  Pozícia dát: {metadata['start_pos']} - {metadata['end_pos']}")

            data_bits = self._extract_bits_from_image(
                image, 
                metadata['storage_method'], 
                metadata['start_pos'], 
                metadata['end_pos']
            )

            output_path = os.path.join(output_dir, metadata['filename'])
            
            if metadata['is_file']:
                self._bits_to_file(data_bits, output_path)
                print(f"Súbor bol extrahovaný ako: {output_path}")
            else:
                # Pre text
                text_content = self._bits_to_text(data_bits)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(text_content)
                print(f"Text bol extrahovaný ako: {output_path}")
            
            return True
            
        except Exception as e:
            print(f"Chyba pri extrakcii súboru: {e}")
            return False


def main():
    """Hlavná funkcia programu."""
    stego = SteganographyTool()
    
    while True:
        print("\n" + "="*50)
        print("STEGANOGRAFICKÝ NÁSTROJ")
        print("="*50)
        print("1. Ukryť text (zadaný v programe)")
        print("2. Ukryť súbor do obrázka")
        print("3. Extrahovať dáta z obrázka")
        print("4. Zobraziť informácie o metódách ukrývania")
        print("0. Ukončiť")
        print("-"*50)
        
        choice = input("Vyberte možnosť (0-4): ").strip()
        
        if choice == '0':
            print("Ďakujem za použitie programu!")
            break
            
        elif choice == '1':
            print("\nUKRÝVANIE TEXTU")
            print("-"*30)
            image_path = input("Cesta k pôvodnému obrázku: ").strip()
            
            print("\nZadajte text na ukrytie:")
            print("(Pre ukončenie zadania napíšte 'END' na samostatný riadok)")
            text_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                text_lines.append(line)
            
            text = '\n'.join(text_lines)
            if not text.strip():
                print("Nebol zadaný žiadny text!")
                continue
                
            output_path = input("Cesta k výstupnému obrázku: ").strip()
            
            print("\nMetódy ukrývania:")
            print("0 - Každý pixel")
            print("1 - Každý párny pixel")
            print("2 - Každý nepárny pixel") 
            print("3 - Pixely na okrajoch obrázka")
            
            try:
                method = int(input("Vyberte metódu (0-3): ").strip())
                if method not in [0, 1, 2, 3]:
                    print("Neplatná metóda!")
                    continue
                    
                stego.hide_text(image_path, text, output_path, method)
                
            except ValueError:
                print("Neplatné číslo!")
                
        elif choice == '2':
            print("\nUKRÝVANIE SÚBORU")
            print("-"*30)
            image_path = input("Cesta k pôvodnému obrázku: ").strip()
            file_path = input("Cesta k súboru na ukrytie: ").strip()
            output_path = input("Cesta k výstupnému obrázku: ").strip()
            
            print("\nMetódy ukrývania:")
            print("0 - Každý pixel")
            print("1 - Každý párny pixel")
            print("2 - Každý nepárny pixel") 
            print("3 - Pixely na okrajoch obrázka")
            
            try:
                method = int(input("Vyberte metódu (0-3): ").strip())
                if method not in [0, 1, 2, 3]:
                    print("Neplatná metóda!")
                    continue
                    
                stego.hide_file(image_path, file_path, output_path, method)
                
            except ValueError:
                print("Neplatné číslo!")
                
        elif choice == '3':
            print("\nEXTRAKCIA DÁT")
            print("-"*30)
            stego_path = input("Cesta k obrázku s ukrytými dátami: ").strip()
            output_dir = input("Adresár pre extrahované dáta (Enter = aktuálny): ").strip()
            
            if not output_dir:
                output_dir = "."
                
            stego.extract_file(stego_path, output_dir)
            
        elif choice == '4':
            print("\nMETÓDY UKRÝVANIA")
            print("-"*30)
            print("0 - Každý pixel:")
            print("    Ukládá data postupně do všech pixelů obrázku")
            print("    Nejvyšší kapacita, ale nejvíce nápadné")
            print()
            print("1 - Každý sudý pixel:")
            print("    Ukládá data pouze do pixelů na sudých pozicích")
            print("    Poloviční kapacita, méně nápadné")
            print()
            print("2 - Každý lichý pixel:")
            print("    Ukládá data pouze do pixelů na lichých pozicích")
            print("    Poloviční kapacita, méně nápadné")
            print()
            print("3 - Okraje obrázku:")
            print("    Ukládá data pouze do pixelů na okrajích")
            print("    Nejmenší kapacita, ale nejméně nápadné")
            
        else:
            print("Neplatná volba!")


if __name__ == "__main__":
    main()
