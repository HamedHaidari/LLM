# anonymizer.py

import spacy
from paddleocr import PaddleOCR
from PIL import Image, ImageDraw
import os
import requests
import json
import re

def load_sensitivity_rules(config_file='sensitive_data_rules.txt'):
    """
    Lädt Regeln zur Erkennung sensibler Daten aus einer Konfigurationsdatei.
    
    Args:
        config_file: Pfad zur Konfigurationsdatei
        
    Returns:
        Dictionary mit Regeln für sensible Daten
    """
    rules = {
        'entities': [],    # spaCy Entitätstypen
        'keywords': [],    # Stichwörter
        'regex': []        # Reguläre Ausdrücke
    }
    
    # Standardregeln, falls keine Datei gefunden wird
    default_rules = {
        'entities': ['PERSON', 'PER', 'ORG', 'LOC', 'GPE', 'FAC', 'DATE'],
        'keywords': ['patient', 'geburt', 'birth', 'vorname', 'nachname'],
        'regex': [r'\b[A-Z0-9]{6,10}\b', r'\d{1,2}[./-]\d{1,2}[./-]\d{2,4}']
    }
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Überspringe leere Zeilen und Kommentarzeilen
                    if not line or line.startswith('#'):
                        continue
                        
                    if ':' in line:
                        rule_type, value = line.split(':', 1)
                        if rule_type == 'entity':
                            rules['entities'].append(value)
                        elif rule_type == 'keyword':
                            rules['keywords'].append(value)
                        elif rule_type == 'regex':
                            rules['regex'].append(value)
            
            print(f"Konfigurationsdatei '{config_file}' erfolgreich geladen:")
            print(f"- {len(rules['entities'])} Entitätstypen")
            print(f"- {len(rules['keywords'])} Schlüsselwörter")
            print(f"- {len(rules['regex'])} Regex-Muster")
        else:
            print(f"Konfigurationsdatei '{config_file}' nicht gefunden. Verwende Standardregeln.")
            return default_rules
    except Exception as e:
        print(f"Fehler beim Laden der Konfigurationsdatei: {e}")
        print("Verwende Standardregeln.")
        return default_rules
        
    # Prüfe, ob Regeln leer sind, und verwende in dem Fall die Standardregeln
    for rule_type, values in rules.items():
        if not values:
            rules[rule_type] = default_rules[rule_type]
            print(f"Keine {rule_type} in Konfigurationsdatei gefunden. Verwende Standardregeln.")
    
    return rules


def ask_ollama(text, model="qwen2.5vl:3b", retries=1, server_url="http://localhost:11434"):
    """
    Fragt das Ollama LLM, ob ein bestimmter Text persönliche oder sensible Informationen enthält.
    
    Args:
        text: Der zu analysierende Text
        model: Das zu verwendende Ollama-Modell (Standard: qwen2.5vl:3b)
        retries: Anzahl der Wiederholungsversuche bei Fehlern
        server_url: URL des Ollama-Servers (Standard: http://localhost:11434)
        
    Returns:
        True wenn der Text sensible Informationen enthält, sonst False
    """
    # Bei leerem Text direkt zurückkehren
    if not text or text.strip() == "":
        return False
        
    # Zu lange Texte können Probleme verursachen, daher kürzen
    if len(text) > 1000:
        text = text[:1000] + "..."
    
    for attempt in range(retries + 1):
        try:
            # Erstelle eine Prompt-Anfrage für das Modell
            prompt = f"""Analyze the following text and determine if it contains personal information or sensitive data that should be anonymized.

Look specifically for:
1. Personal names (first name, last name, Vorname, Nachname) in both English and German
2. Patient IDs or any reference numbers for patients
3. Birth dates or any dates that could be birth dates (in any format like DD.MM.YYYY, MM/DD/YYYY, etc.)
4. Addresses, phone numbers, email addresses
5. Any medical or health-related personal information
6. Academic credentials that could identify specific people

The text is from a document OCR scan. Answer only with 'YES' if it contains any personal or sensitive info, or 'NO' if it does not:
        
Text: {text}
"""
              # Sende die Anfrage an den Ollama API-Endpunkt
            try:
                api_url = f"{server_url}/api/generate"
                response = requests.post(
                    api_url,
                    json={"model": model, "prompt": prompt, "stream": False},
                    timeout=20  # 10 Sekunden Timeout
                )
                
                if response.status_code == 200:
                    result = response.json()
                    answer = result.get("response", "").strip().upper()
                    
                    # Prüfe, ob die Antwort ein klares JA enthält
                    return "YES" in answer.split()
                elif response.status_code == 500:
                    # Bei einem 500er Fehler vom Server könnte es ein Modell-Problem sein
                    print(f"HTTP 500 Fehler vom Ollama-Server - Versuch {attempt+1}/{retries+1}")
                    if attempt < retries:
                        print("Wiederhole Anfrage in 2 Sekunden...")
                        import time
                        time.sleep(2)
                        continue
                    else:
                        print("Alle Wiederholungsversuche fehlgeschlagen. Fahre ohne LLM-Verifikation fort.")
                        return True  # Im Zweifelsfall als sensibel behandeln
                else:
                    print(f"Fehler bei der Ollama-API-Anfrage: Status {response.status_code}")
                    if attempt < retries:
                        continue
                    return True  # Im Zweifelsfall als sensibel behandeln
            
            except requests.exceptions.Timeout:
                print("Timeout bei der Anfrage an den Ollama-Server")
                if attempt < retries:
                    continue
                return True  # Im Zweifelsfall als sensibel behandeln
                
            except requests.exceptions.ConnectionError:
                print("Verbindungsfehler: Konnte keine Verbindung zum Ollama-Server herstellen")
                print("Ist der Ollama-Server gestartet? (Standard: http://localhost:11434)")
                return True  # Im Zweifelsfall als sensibel behandeln
                
        except Exception as e:
            print(f"Fehler bei der Verwendung des Ollama-Modells: {e}")
            if attempt < retries:
                continue
            return True  # Im Zweifelsfall als sensibel behandeln
    
    # Wenn wir hierher gelangen, haben alle Versuche fehlgeschlagen
    return True  # Im Zweifelsfall als sensibel behandeln
        
def list_ollama_models(timeout=5, server_url="http://localhost:11434"):
    """
    Listet die verfügbaren Ollama-Modelle auf und gibt sie zurück
    
    Args:
        timeout: Timeout für die Anfrage in Sekunden
        server_url: URL des Ollama-Servers (Standard: http://localhost:11434)
        
    Returns:
        Liste der verfügbaren Modellnamen oder leere Liste bei Fehlern
    """
    try:
        try:
            api_url = f"{server_url}/api/tags"
            response = requests.get(api_url, timeout=timeout)
            
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [model["name"] for model in models]
                
                if model_names:
                    print(f"Verfügbare Ollama-Modelle: {', '.join(model_names)}")
                else:
                    print("Keine Ollama-Modelle auf dem Server gefunden.")
                    
                return model_names
            elif response.status_code == 500:
                print(f"Interner Serverfehler (500) beim Abrufen der Ollama-Modelle")
                print("Möglicherweise ist das Modell nicht geladen oder ein anderer Serverfehler ist aufgetreten.")
                return []
            else:
                print(f"Fehler beim Abrufen der Ollama-Modelle: Status {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            print(f"Timeout beim Verbinden mit dem Ollama-Server (nach {timeout} Sekunden)")
            return []
            
        except requests.exceptions.ConnectionError:
            print("Verbindungsfehler: Ollama-Server scheint nicht zu laufen")
            print("Bitte starten Sie den Ollama-Server oder deaktivieren Sie die LLM-Funktion mit --nollm")
            return []
            
    except Exception as e:
        print(f"Unerwarteter Fehler beim Abrufen der Ollama-Modelle: {e}")
        return []

def extract_sensitive_values(text, key_indicators):
    """
    Extrahiert sensible Werte basierend auf Schlüsselwörtern im Text.
    Beispiel: Bei "First Name: Hamed" wird "Hamed" als sensibler Wert erkannt, nicht "First Name".
    Funktioniert auch mit strukturierten Dokumenten wie Pässen und Ausweisen.
    
    Args:
        text: Der zu analysierende Text
        key_indicators: Liste von Schlüsselwörtern, die auf sensible Werte hinweisen
        
    Returns:
        Liste von Tupeln mit (start_pos, end_pos, value) für jeden gefundenen sensiblen Wert
    """
    sensitive_values = []
    
    # Regulärer Ausdruck für gängige Trennzeichen zwischen Label und Wert
    # z.B. "Name: Hamed", "Geburtsdatum - 01.01.1990", "ID# 12345"
    separators = [r':', r'-', r'\s{2,}', r'#', r'=', r'\|', r'>', r'\.{2,}', r'/', r'\\']
    separator_pattern = '|'.join(separators)
    
    # Spezieller Fall für Dokumente wie Pässe/Ausweise: Suche nach Zeilenumbruch oder Seitenende
    # In solchen Dokumenten ist oft ein Schlüsselwort und der Wert unmittelbar daneben oder darunter
    doc_separators = [r'\n', r'\r', r'\t']
    
    text_lower = text.lower()
    
    # 1. Methode: Suche nach Schlüsselwörtern und extrahiere Werte
    for key in key_indicators:
        key_lower = key.lower()
        if key_lower in text_lower:
            # Finde Position des Schlüsselworts
            key_pos = text_lower.find(key_lower)
            
            # Suche nach dem Trennzeichen nach dem Schlüsselwort
            remaining_text = text[key_pos + len(key):]
            separator_match = re.search(f"({'|'.join(separators)})", remaining_text)
            
            if separator_match:
                # Extrahiere den Wert nach dem Trennzeichen
                sep_pos = separator_match.start()
                value_start = key_pos + len(key) + sep_pos + len(separator_match.group())
                
                # Finde das Ende des Wertes (bis zum nächsten Trennzeichen, Zeilenumbruch oder Ende des Textes)
                end_patterns = separators + doc_separators + [r',', r';']
                next_separator = re.search(f"({'|'.join(end_patterns)})", text[value_start:])
                if next_separator:
                    value_end = value_start + next_separator.start()
                else:
                    value_end = len(text)
                
                # Trimme den Wert und füge ihn hinzu, wenn er nicht leer ist
                value = text[value_start:value_end].strip()
                if value:
                    sensitive_values.append((value_start, value_end, value))
            else:
                # Fall: Kein explizites Trennzeichen, nehme den Rest des Textes
                # Dieser Fall ist typisch für kurze Texte wie "Name Hamed"
                if key_pos + len(key) < len(text):
                    value = text[key_pos + len(key):].strip()
                    if value:
                        sensitive_values.append((key_pos + len(key), len(text), value))
    
    # 2. Methode: Suche nach strukturierten Datenformaten, die typisch für Pässe/Ausweise sind
    # Beispiel: Passnummern (oft mit Muster wie 2 Buchstaben + 7 Zahlen)
    passport_patterns = [
        (r'\b[A-Z]{1,2}[0-9]{6,8}\b', "Passnummer"),      # Typisches Passnummernformat
        (r'P<[A-Z]{3}[A-Z0-9]{7,9}', "MRZ-Identifikator"), # P<DEU Format im MRZ
        (r'\b[0-9]{9}\b', "Personalausweis/ID"),           # 9-stellige ID-Nummer
        (r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b', "Sozialversicherungsnummer"),  # SSN-Format
        (r'\b[A-Z]\s?[0-9]{7}\b', "Reisepassnummer"),      # Deutsches Passnummernformat
        (r'\b[A-Z]{2}\s?[0-9]{6}\b', "Ausländische ID"),   # Ausländischer Ausweis
        (r'\b[0-9]{2}\s[0-9]{2}\s[0-9]{2}\b', "Geburtsdatum") # Typisches Datumsformat in Ausweisen
    ]
    
    for pattern, label in passport_patterns:
        for match in re.finditer(pattern, text):
            sensitive_values.append((match.start(), match.end(), match.group()))
    
    # 3. Suche nach kontextuellen Hinweisen im Pass-Format
    # Bei manchen Ausweisen/Pässen ist das Format: "P<AUSSTELLUNGSLAND<NACHNAME<<VORNAME<..."
    if "<<" in text or "P<" in text:
        parts = re.split(r'[<>]+', text)
        for part in parts:
            part = part.strip()
            if len(part) > 1 and part.isalpha() and not part.lower() in ["p", "pass", "passport"]:
                start_pos = text.find(part)
                if start_pos != -1:
                    sensitive_values.append((start_pos, start_pos + len(part), part))
    
    return sensitive_values

def get_sensitive_regions(text, doc, sensitivity_rules):
    """
    Identifiziert Regionen im Text, die sensible Informationen enthalten.
    Optimiert für verschiedene Dokumenttypen wie Pässe, Ausweise und medizinische Dokumente.
    
    Args:
        text: Der zu analysierende Text
        doc: Das spaCy-Doc-Objekt
        sensitivity_rules: Dict mit Regeln zur Erkennung sensibler Daten
        
    Returns:
        Liste von Regionen (start, end, text) die geschwärzt werden sollten
    """
    regions_to_redact = []
    
    # 1. Erkenne benannte Entitäten direkt (Namen, Orte, etc.)
    sensitive_entity_types = sensitivity_rules['entities']
    for ent in doc.ents:
        if ent.label_ in sensitive_entity_types:
            # Füge die gesamte Entität hinzu
            regions_to_redact.append((ent.start_char, ent.end_char, ent.text))
    
    # 2. Extrahiere Werte neben Schlüsselwörtern
    sensitive_values = extract_sensitive_values(text, sensitivity_rules['keywords'])
    regions_to_redact.extend(sensitive_values)
    
    # 3. Erkenne gängige Muster mit regulären Ausdrücken
    for pattern in sensitivity_rules['regex']:
        try:
            for match in re.finditer(pattern, text):
                regions_to_redact.append((match.start(), match.end(), match.group()))
        except re.error:
            print(f"Warnung: Ungültiges Regex-Muster: {pattern}")
    
    # 4. Spezielle Dokumententypen erkennen und behandeln
    # Reisepässe und ID-Karten haben oft MRZ-Zeilen (maschinenlesbare Zone)
    # Diese bestehen aus 2-3 Zeilen mit Großbuchstaben, Zahlen und < Zeichen
    if any(line.isupper() and '<' in line for line in text.split('\n')):
        for line in text.split('\n'):
            # MRZ-Erkennung stärker machen: Typische Muster für MRZ-Zeilen
            mrz_patterns = [
                r'P<[A-Z]{3}',             # Beginn der MRZ-Zeile, P<DEU
                r'[A-Z0-9]{9}<<[A-Z0-9]',  # 9 Zeichen gefolgt von << und mindestens einem weiteren Zeichen
                r'\d{6}[FM]\d{7}',         # Geburtsdatum (6 Ziffern) + Geschlecht + 7 Ziffern
                r'[A-Z0-9<]{30,44}'        # MRZ-Zeilen haben eine feste Länge (zwischen 30-44 Zeichen)
            ]
            
            is_mrz = False
            if line.isupper() and '<' in line:
                # Prüfe, ob die Zeile MRZ-Kriterien erfüllt
                if len(line) >= 30 and any(re.search(pattern, line) for pattern in mrz_patterns):
                    is_mrz = True
                # Weitere Tests: MRZ hat oft viele aufeinanderfolgende < Zeichen
                if '<<' in line and line.count('<') > 5:
                    is_mrz = True
                # Test auf Geburtsdatumsformat: 6 aufeinanderfolgende Ziffern in Kombination mit < Zeichen
                if re.search(r'\d{6}', line) and '<' in line:
                    is_mrz = True
            
            if is_mrz:
                # Typische MRZ-Zeile gefunden - schwärze sie komplett
                start_pos = text.find(line)
                if start_pos != -1:
                    regions_to_redact.append((start_pos, start_pos + len(line), line))
                    print(f"MRZ-Zeile erkannt: {line}")
    
    # 5. Deduplizieren der gefundenen Regionen und zusammenführen überlappender Bereiche
    if regions_to_redact:
        # Sortiere nach Startposition
        regions_to_redact.sort(key=lambda x: x[0])
        
        merged_regions = []
        current = regions_to_redact[0]
        
        for next_region in regions_to_redact[1:]:
            # Wenn sich die Regionen überlappen oder direkt aneinander grenzen
            if next_region[0] <= current[1]:
                # Erweitere die aktuelle Region
                end = max(current[1], next_region[1])
                value = text[current[0]:end]
                current = (current[0], end, value)
            else:
                # Keine Überlappung, füge die aktuelle Region hinzu und gehe zur nächsten über
                merged_regions.append(current)
                current = next_region
        
        # Füge die letzte Region hinzu
        merged_regions.append(current)
        
        return merged_regions
    
    return regions_to_redact

def anonymize_document(image_path: str, output_path: str, use_llm=True, ollama_model="qwen2.5vl:3b", 
                     config_file="sensitive_data_rules.txt", debug_mode=False, is_passport=False):
    """
    Diese Funktion anonymisiert Personenamen in einem Dokument (Bilddatei).

    Der Prozess:
    1. Extrahiert Text und seine Koordinaten mit PaddleOCR.
    2. Findet Personennamen und sensible Informationen mit spaCy.
    3. Verifiziert mit einem LLM (Ollama), ob der Text wirklich sensibel ist.
    4. Zeichnet schwarze Balken über sensible Informationen auf dem Originalbild.
    
    Parameter:
        image_path: Pfad zur Bilddatei
        output_path: Pfad zum Ausgabebild
        use_llm: Ob ein LLM zur Verifikation verwendet werden soll
        ollama_model: Name des zu verwendenden Ollama-Modells
        config_file: Pfad zur Konfigurationsdatei
        debug_mode: Ob detaillierte Debug-Informationen ausgegeben werden sollen
        is_passport: Ob es sich um einen Pass/Ausweis handelt
    """
    print("Lade KI-Modelle und Konfiguration... (dies kann einen Moment dauern)")
    
    # Lade die Sensitivitätsregeln aus der Konfigurationsdatei
    sensitivity_rules = load_sensitivity_rules(config_file)
    
    # 1. Lade die KI-Modelle
    # PaddleOCR für die Texterkennung
    import paddle
    paddle.device.cuda.empty_cache()
    ocr = PaddleOCR(lang='en', 
                    device='gpu',
                    use_doc_orientation_classify=False, 
                    use_doc_unwarping=False, 
                    use_textline_orientation=False)

    
    # spaCy für die Erkennung von benannten Entitäten (NER)
    # Wir laden ein umfassenderes Modell, wenn verfügbar
    try:
        nlp = spacy.load("en_core_web_trf")  # Versuche das große Modell zu laden
        print("Verwende erweitertes spaCy-Modell (en_core_web_trf)")
    except:
        try:
            nlp = spacy.load("en_core_web_md")  # Versuche das mittlere Modell
            print("Verwende mittleres spaCy-Modell (en_core_web_md)")
        except:
            nlp = spacy.load("en_core_web_sm")  # Fallback auf kleines Modell
            print("Verwende Standard spaCy-Modell (en_core_web_sm)")
      # Prüfe, ob LLM-Unterstützung aktiviert und verfügbar ist
    if use_llm:
        print("Prüfe verfügbare Ollama-Modelle...")
        try:
            available_models = list_ollama_models(timeout=10)  # Längerer Timeout für ersten Aufruf
            
            if available_models:
                if ollama_model not in available_models:
                    print(f"Warnung: Angegebenes Modell '{ollama_model}' nicht gefunden.")
                    
                    # Versuche ähnliche Modelle zu finden oder alternativ den ersten verfügbaren zu nehmen
                    similar_models = [m for m in available_models if ollama_model.lower().split(':')[0] in m.lower()]
                    if similar_models:
                        print(f"Verwende ähnliches Modell: {similar_models[0]}")
                        ollama_model = similar_models[0]
                    else:
                        print(f"Verwende erstes verfügbares Modell: {available_models[0]}")
                        ollama_model = available_models[0]
                
                print(f"Verwende Ollama-LLM-Modell: {ollama_model}")
                
                # Warme-up-Anfrage, um zu prüfen, ob das Modell funktioniert
                print("Teste Verbindung zum Ollama-Server...")
                warm_up_test = ask_ollama("Test text to check if model responds", model=ollama_model)
                print("Ollama-LLM bereit für Verifikation.")
            else:
                print("Keine Ollama-Modelle verfügbar oder Server nicht erreichbar.")
                print("LLM-Verifikation wird deaktiviert. Verwenden Sie --nollm als Parameter oder starten Sie den Ollama-Server.")
                use_llm = False
        except Exception as e:
            print(f"Fehler bei der Initialisierung des LLM: {e}")
            print("LLM-Verifikation wird deaktiviert.")
            use_llm = False
    
    print(f"Verarbeite Dokument: {image_path}")
    
    # Öffne das Bild, um darauf zu zeichnen
    image = Image.open(image_path)
    draw = ImageDraw.Draw(image)
    
    # 2. Führe OCR auf dem gesamten Dokument aus
    results = ocr.predict(image_path)
    
    # Bildgröße ermitteln für relative Positionsbestimmung
    img_width, img_height = image.size
      # Pass/Ausweis-Erkennung: Überprüfe das Gesamtdokument auf typische Ausweismerkmale
    is_likely_passport = is_passport  # Verwende den Parameter, wenn explizit angegeben
    
    # Debug-Info
    if debug_mode:
        print(f"Debug-Modus aktiv: Detaillierte Informationen werden angezeigt")
        print(f"Bildgröße: {img_width}x{img_height} Pixel")
    
    # Extrahiere Gesamttext für Passtyperkennung
    full_document_text = ""
    
    # PaddleOCR gibt eine Liste zurück
    if results and len(results) > 0:
        # Das Dictionary enthält separate Listen für Koordinaten und Texte
        result_dict = results[0]
        if 'dt_polys' in result_dict and 'rec_texts' in result_dict:
            boxes = result_dict['dt_polys']  # Liste aller Koordinaten-Boxen
            texts = result_dict['rec_texts'] # Liste aller erkannten Texte

            # Kombiniere alle erkannten Texte für eine Gesamtanalyse
            full_document_text = " ".join(texts)
            
            if debug_mode:
                print(f"Erkannter Gesamttext:\n{full_document_text[:200]}...")
            
            # Überprüfe, ob es sich wahrscheinlich um einen Pass/Ausweis handelt
            passport_indicators = ["reisepass", "passport", "identity card", "personalausweis", 
                               "visa", "national id", "driving licence", "führerschein", 
                               "ausweis", "ausstellung", "gültig bis", "nationality"]
              # Wenn nicht explizit als Pass angegeben, prüfen wir automatisch
            if not is_passport:
                if any(indicator in full_document_text.lower() for indicator in passport_indicators):
                    is_likely_passport = True
                    print("Dokumenttyp: Pass oder Ausweis erkannt!")
                    
                    if debug_mode:
                        # Zeige, welche Indikatoren gefunden wurden
                        found_indicators = [ind for ind in passport_indicators if ind in full_document_text.lower()]
                        print(f"Gefundene Pass-Indikatoren: {', '.join(found_indicators)}")
                
                # Suche nach MRZ-Zeilen im Gesamttext (typisch für Pässe)
                has_mrz_lines = False
                mrz_lines = []
                for line in full_document_text.split('\n'):
                    if line.isupper() and '<' in line and len(line.strip()) > 20:
                        has_mrz_lines = True
                        mrz_lines.append(line)
                
                if has_mrz_lines:
                    is_likely_passport = True
                    print("MRZ-Zeilen erkannt: Dokument ist wahrscheinlich ein Pass oder Ausweis!")
                    
                    if debug_mode:                        
                        print(f"Gefundene MRZ-Zeilen:")
                        for idx, line in enumerate(mrz_lines):
                            print(f"  {idx+1}. {line}")
                            
            print(f"{len(texts)} Textblöcke gefunden.")
            
            # Wenn es sich um einen Pass handelt, wende spezielle Passanalyse an
            if is_likely_passport:
                print("Anwendung spezieller Algorithmen für Passanalyse...")
                
            # Wir müssen nun über den Index gehen, um die passenden Boxen und Texte zu finden.
            for i in range(len(texts)):
                box_coordinates = boxes[i]
                
                # Validiere die Bounding Box - Überprüfe auf ungültige oder extrem große Boxen
                if len(box_coordinates) != 4:
                    if debug_mode:
                        print(f"  Überspringe ungültige Box für Textblock {i+1}")
                    continue
                  # Prüfe auf extrem große oder ungültige Boxen
                x_min, y_min = min(point[0] for point in box_coordinates), min(point[1] for point in box_coordinates)
                x_max, y_max = max(point[0] for point in box_coordinates), max(point[1] for point in box_coordinates)
                box_width, box_height = x_max - x_min, y_max - y_min
                
                # Übermäßig große Boxen können Probleme verursachen
                if box_width > img_width * 0.9 or box_height > img_height * 0.9:
                    if debug_mode:
                        print(f"  Überspringe zu große Box für Textblock {i+1}: {box_width}x{box_height}")
                    continue
                
                text = texts[i]
                  # Überspringe leeren oder problematischen Text
                if not text or len(text.strip()) == 0:
                    if debug_mode:
                        print(f"  Überspringe leeren Textblock {i+1}")
                    continue
                
                # Prüfe auf seltsame Zeichen oder extrem kurzen Text, die Probleme verursachen können
                if len(text.strip()) < 2 or not any(c.isalnum() for c in text):
                    if debug_mode:
                        print(f"  Überspringe problematischen Text: '{text}'")
                    continue
                
                try:
                    # Schritt 1: Analysiere den erkannten Text mit spaCy
                    # Wir begrenzen die Länge des Texts, um Speicherprobleme zu vermeiden
                    text_to_process = text[:1000]  # Begrenze auf 1000 Zeichen
                    doc = nlp(text_to_process)
                except Exception as e:  # Fängt alle möglichen Fehler ab, nicht nur ValueError
                    print(f"Fehler bei der Verarbeitung von Text durch spaCy: {e}")
                    print(f"Problematischer Text: '{text}'")
                    # Fahre ohne NLP-Analyse fort
                    doc = None
                    continue  # Skip this text block and move to the next one
                
                # Lade die Sensitivitätsregeln (Entitäten, Schlüsselwörter, Regex) aus der Konfigurationsdatei
                sensitivity_rules = load_sensitivity_rules('sensitive_data_rules.txt')
                  # Debug-Information für den aktuellen Textblock
                if debug_mode:
                    print(f"\nVerarbeite Textblock {i+1}/{len(texts)}:")
                    print(f"  Text: {text[:50]}..." if len(text) > 50 else f"  Text: {text}")
                    print(f"  Position: {box_coordinates[0]} - {box_coordinates[2]}")
                
                # Spezielle Passverarbeitung, wenn das Dokument als Pass erkannt wurde
                passport_elements = None
                if is_likely_passport:
                    if debug_mode:
                        print(f"  Analysiere Textblock auf Pass-Elemente...")
                    
                    passport_elements = detect_passport_structure(text, box_coordinates, img_width, img_height)
                    
                    # Wenn Passelemente erkannt wurden, füge sie den sensiblen Regionen hinzu
                    if passport_elements and passport_elements['sensitive_regions']:
                        print(f"Pass-Elemente erkannt im Block: {text}")
                        for element_type, value in passport_elements.items():
                            if element_type != 'sensitive_regions' and value and value != "":
                                print(f"  - {element_type}: {value}")
                                
                                # Bei erkannten MRZ-Zeilen verwenden wir unseren spezialisierten Parser
                                if element_type == 'mrz_lines' and len(value) > 0:
                                    print("MRZ-Zeilen gefunden, analysiere mit speziellem Parser...")
                                    mrz_info = parse_passport_mrz(value)
                                    for mrz_key, mrz_value in mrz_info.items():
                                        if mrz_value and mrz_value != "":
                                            print(f"  --> MRZ-{mrz_key}: {mrz_value}")
                    elif debug_mode and not passport_elements['sensitive_regions']:
                        print("  Keine Pass-Elemente in diesem Textblock erkannt.")
                
                # Identifiziere sensible Regionen - hier konzentrieren wir uns auf die Werte, nicht die Schlüsselwörter
                sensitive_regions = get_sensitive_regions(text, doc, sensitivity_rules)
                
                # Füge erkannte Pass-Elemente zu den sensiblen Regionen hinzu
                if passport_elements and passport_elements['sensitive_regions']:
                    sensitive_regions.extend(passport_elements['sensitive_regions'])
                    
                    # Bei erkannten Passelementen: Prüfe, ob es sich um sensible Werte wie Namen, Geburtsdatum usw. handelt
                    for element_type, value in passport_elements.items():
                        if element_type in ['name', 'birthdate', 'passport_number'] and value and value != "":
                            # Suche nach dem exakten Wert im Text und schwärze ihn
                            value_start = text.find(value)
                            if value_start != -1:
                                sensitive_regions.append((value_start, value_start + len(value), value))
                    
                    # Deduplizieren der Regionen nach dem Hinzufügen
                    seen = set()
                    unique_regions = []
                    for region in sensitive_regions:
                        region_key = (region[0], region[1])  # start, end als Schlüssel
                        if region_key not in seen:
                            seen.add(region_key)
                            unique_regions.append(region)
                    sensitive_regions = unique_regions
                
                # Wenn wir sensible Regionen gefunden haben, markiere sie für die Anonymisierung
                has_sensitive_content = len(sensitive_regions) > 0
                
                # Alternativ, wenn wir akademische Muster finden, könnten wir den gesamten Block schwärzen
                contains_academic_pattern = (
                    ("publication" in text.lower()) or
                    ("citations" in text.lower()) or
                    ("university" in text.lower()) or
                    ("profile" in text.lower()) or
                    ("author" in text.lower())
                )
                
                # Für die Kompatibilität mit dem LLM-Check
                should_anonymize = has_sensitive_content or contains_academic_pattern
                if should_anonymize and use_llm and text.strip():
                    # LLM-Verifikation, um Fehlalarme zu reduzieren
                    try:
                        # Für Pass-Elemente direkt anonymisieren ohne LLM-Check
                        if is_likely_passport and any(pass_word in text.lower() for pass_word in ["pass", "ausweis", "id", "mrz"]):
                            if debug_mode:
                                print(f"--> Pass-Element erkannt, LLM-Verifikation übersprungen für: '{text}'")
                        else:
                            # Versuche LLM-Verifikation mit Wiederholungsversuchen bei Fehlern
                            should_anonymize = ask_ollama(text, model=ollama_model, retries=2)
                            if not should_anonymize:
                                print(f"--> LLM hat entschieden, dass dieser Text KEINE sensible Information enthält: '{text}'")
                    except Exception as e:
                        if debug_mode:
                            print(f"--> Fehler bei LLM-Verifikation: {e}. Behandle Text als sensibel.")
                        # Im Fehlerfall als sensibel behandeln
                        should_anonymize = True
                # Schwärze den Text, wenn sensible Entitäten gefunden wurden oder akademische Muster
                if should_anonymize:                    # Ausgabe der gefundenen sensiblen Werte
                    if len(sensitive_regions) > 0:
                        for start, end, value in sensitive_regions:
                            print(f"--> Sensibler Wert gefunden: '{value}' im Text '{text}'")
                    
                    if contains_academic_pattern:
                        print(f"--> Akademische Information gefunden: '{text}'")
                        
                    # Konvertiere die Koordinaten in eine Form, die wir verwenden können
                    points = []
                    for point in box_coordinates:
                        if hasattr(point, 'tolist'):  # Wenn es ein numpy-Array ist
                            points.append(tuple(point.tolist()))
                        else:
                            points.append(tuple(point))
                    
                    # Berechne das umschließende Rechteck für den ganzen Textblock
                    x_coords = [p[0] for p in points]
                    y_coords = [p[1] for p in points]
                    
                    # Umschließendes Rechteck
                    block_top_left = (min(x_coords), min(y_coords))
                    block_bottom_right = (max(x_coords), max(y_coords))
                    
                    # Gesamtbreite und -höhe des Textblocks
                    block_width = block_bottom_right[0] - block_top_left[0]
                    block_height = block_bottom_right[1] - block_top_left[1]
                    
                    if contains_academic_pattern:
                        # Bei akademischen Mustern schwärzen wir den ganzen Block
                        draw.rectangle([block_top_left, block_bottom_right], fill="black")
                        print(f"    --> Kompletter Block bei {block_top_left}/{block_bottom_right} geschwärzt (akademisches Muster).")
                    elif len(sensitive_regions) > 0:
                        # Bei sensiblen Werten schwärzen wir nur die entsprechenden Teile
                        for start, end, value in sensitive_regions:
                            # Berechne die relative Position im Text
                            rel_start = start / len(text)
                            rel_end = end / len(text)
                            
                            # Berechne die absolute Position auf dem Bild
                            value_left = int(block_top_left[0] + rel_start * block_width)
                            value_right = int(block_top_left[0] + rel_end * block_width)
                              # Schwärze den Bereich
                            redact_top_left = (value_left, block_top_left[1])
                            redact_bottom_right = (value_right, block_bottom_right[1])
                            draw.rectangle([redact_top_left, redact_bottom_right], fill="black")
                            print(f"    --> Sensibler Wert '{value}' bei {redact_top_left}/{redact_bottom_right} geschwärzt.")
    
    # 4. Speichere das anonymisierte Bild
    image.save(output_path)
      # Zusammenfassung der Dokumentenanalyse ausgeben
    if is_likely_passport:
        print("\n=== Zusammenfassung der Pass-/Ausweis-Erkennung ===")
        
        # Sammle die erkannten MRZ-Zeilen für die spätere Analyse
        all_mrz_lines = []
        
        # Sammle allgemeine Passinformationen, die erkannt wurden
        passport_info = {
            "name": "",
            "birthdate": "",
            "passport_number": "",
            "nationality": "",
            "issue_date": "",
            "expiry_date": "",
            "issuing_authority": ""
        }
        if debug_mode:
            print("Debug-Informationen zur Passerkennung:")
            print(f"- Pass/Ausweis-Modus: {'Aktiviert' if is_passport else 'Automatisch erkannt'}")
            print(f"- Analysedetails werden mit --debug angezeigt")
        
        # Suche im vollen Text nach typischen MRZ-Zeilen
        for line in full_document_text.split('\n'):
            if line.isupper() and '<' in line and len(line) >= 30:
                all_mrz_lines.append(line)
                print(f"MRZ-Zeile gefunden: {line}")
        
        # Wenn MRZ-Zeilen gefunden wurden, analysiere sie mit dem spezialisierten Parser
        if all_mrz_lines:
            mrz_info = parse_passport_mrz(all_mrz_lines)
            print("\nInformationen aus der maschinenlesbaren Zone (MRZ):")
            for key, value in mrz_info.items():
                if value and value != "":
                    passport_info[key] = value if key in passport_info else ""
                    print(f"  - {key}: {value}")
        
        # Zeige die erkannten Passinformationen
        print("\nErkannte Passinformationen:")
        for key, value in passport_info.items():
            if value:
                print(f"  - {key}: {value}")
    
    print(f"\nAnonymisiertes Dokument wurde erfolgreich gespeichert unter: {output_path}")


def detect_passport_structure(text, box_coordinates, image_width, image_height):
    """
    Spezialisierte Funktion zur Erkennung und Analyse von Passstrukturen.
    
    Args:
        text: Der erkannte Text aus dem OCR-Prozess
        box_coordinates: Die Koordinaten des Textblocks
        image_width: Breite des Originalbildes
        image_height: Höhe des Originalbildes
        
    Returns:
        Dictionary mit erkannten Elementen und deren Positionen
    """
    detected_elements = {
        'mrz_lines': [],                # Maschinenlesbare Zonen
        'name': None,                   # Name des Passinhabers
        'birthdate': None,              # Geburtsdatum
        'passport_number': None,        # Passnummer
        'expiry_date': None,            # Ablaufdatum
        'sensitive_regions': []         # Zu schwärzende Regionen (start, end, text)
    }
    
    # 1. Typisches Layoutmuster erkennen (Position in der oberen Hälfte = Kopfdaten, untere Abschnitte = MRZ)
    # Berechne die relative Y-Position im Bild
    points = []
    for point in box_coordinates:
        if hasattr(point, 'tolist'):
            points.append(tuple(point.tolist()))
        else:
            points.append(tuple(point))
    
    y_coords = [p[1] for p in points]
    rel_y_pos = min(y_coords) / image_height  # Relative Position von oben
    
    # 2. Text auf spezifische Passelemente analysieren
    text_lower = text.lower()
    
    # Namen erkennen: Nach typischen Schlüsselwörtern suchen
    name_keywords = ["name", "surname", "vorname", "nachname", "given names", "family name"]
    for keyword in name_keywords:
        if keyword in text_lower:
            # Extrahiere den Teil nach dem Schlüsselwort
            key_pos = text_lower.find(keyword)
            remaining = text[key_pos + len(keyword):].strip()
            
            # Suche nach Trennzeichen und nehme alles danach als Namen
            for sep in [":", "/", ">", "-", "=", " "]:
                if sep in remaining:
                    name_candidate = remaining.split(sep, 1)[1].strip()
                    if name_candidate and len(name_candidate) > 2:
                        detected_elements['name'] = name_candidate
                        # Füge diese Region zum Schwärzen hinzu
                        start_pos = text.find(name_candidate)
                        if start_pos != -1:
                            detected_elements['sensitive_regions'].append(
                                (start_pos, start_pos + len(name_candidate), name_candidate)
                            )
                        break
            
            if detected_elements['name']:
                break
    
    # Geburtsdatum erkennen
    date_patterns = [
        r'\b\d{2}[./-]\d{2}[./-]\d{4}\b',    # DD.MM.YYYY, DD/MM/YYYY
        r'\b\d{4}[./-]\d{2}[./-]\d{2}\b',    # YYYY.MM.DD, YYYY/MM/DD
        r'\b\d{2}[./-]\d{2}[./-]\d{2}\b'     # DD.MM.YY, DD/MM/YY
    ]
    
    date_keywords = ["birth", "geboren", "date of birth", "geburtsdatum"]
    
    # Suche nach Datumsmustern in der Nähe von Geburtsdatums-Schlüsselwörtern
    for keyword in date_keywords:
        if keyword in text_lower:
            # Suche in einem Umkreis von 30 Zeichen um das Schlüsselwort
            key_pos = text_lower.find(keyword)
            search_start = max(0, key_pos - 15)
            search_end = min(len(text), key_pos + 30)
            search_area = text[search_start:search_end]
            
            for pattern in date_patterns:
                date_match = re.search(pattern, search_area)
                if date_match:
                    date_str = date_match.group(0)
                    detected_elements['birthdate'] = date_str
                    
                    # Position im Originaltext berechnen
                    match_start = search_start + date_match.start()
                    match_end = search_start + date_match.end()
                    detected_elements['sensitive_regions'].append(
                        (match_start, match_end, date_str)
                    )
                    break
            
            if detected_elements['birthdate']:
                break
    
    # Passnummer erkennen
    passport_keywords = ["passport no", "passnummer", "document no", "ausweisnummer"]
    passport_patterns = [
        r'\b[A-Z]{1,2}[0-9]{6,8}\b',      # Typisches Passnummernformat
        r'\b[0-9]{9}\b',                   # 9-stellige ID-Nummer
        r'\b[A-Z]\s?[0-9]{7}\b',           # Deutsches Passnummernformat
        r'\b[A-Z]{2}\s?[0-9]{6}\b',        # Ausländischer Ausweis
    ]
    
    # Zuerst nach Schlüsselwörtern suchen
    for keyword in passport_keywords:
        if keyword in text_lower:
            key_pos = text_lower.find(keyword)
            search_start = key_pos
            search_end = min(len(text), key_pos + 40)  # Suche in den nächsten 40 Zeichen
            search_area = text[search_start:search_end]
            
            for pattern in passport_patterns:
                passport_match = re.search(pattern, search_area)
                if passport_match:
                    passport_num = passport_match.group(0)
                    detected_elements['passport_number'] = passport_num
                    
                    # Position im Originaltext berechnen
                    match_start = search_start + passport_match.start()
                    match_end = search_start + passport_match.end()
                    detected_elements['sensitive_regions'].append(
                        (match_start, match_end, passport_num)
                    )
                    break
    
    # Falls keine Schlüsselwörter gefunden wurden, suche direkt nach Passnummernmustern
    if not detected_elements['passport_number']:
        for pattern in passport_patterns:
            for match in re.finditer(pattern, text):
                # Prüfe, ob es wahrscheinlich eine Passnummer ist (z.B. nicht Teil eines längeren Texts)
                if (match.start() == 0 or not text[match.start()-1].isalnum()) and \
                   (match.end() == len(text) or not text[match.end()].isalnum()):
                    passport_num = match.group(0)
                    detected_elements['passport_number'] = passport_num
                    detected_elements['sensitive_regions'].append(
                        (match.start(), match.end(), passport_num)
                    )
                    break
      # MRZ-Zeilen erkennen (bereits in der Hauptfunktion enthalten, aber hier nochmal separat)
    mrz_lines = []
    if any(line.isupper() and '<' in line for line in text.split('\n')):
        for line in text.split('\n'):
            if line.isupper() and '<' in line and any(c.isdigit() for c in line):
                if len(line) >= 20 and '<<' in line:  # Typische MRZ-Mindestlänge
                    mrz_lines.append(line)
                    detected_elements['mrz_lines'].append(line)
                    start_pos = text.find(line)
                    if start_pos != -1:
                        detected_elements['sensitive_regions'].append(
                            (start_pos, start_pos + len(line), line)
                        )
    
    # Wenn MRZ-Zeilen gefunden wurden, extrahiere die Informationen daraus
    if mrz_lines:
        mrz_info = parse_passport_mrz(mrz_lines)
        
        # Füge erkannte MRZ-Informationen zum Ergebnis hinzu
        for key, value in mrz_info.items():
            if value and len(value) > 0:
                if key == 'name' and not detected_elements['name']:
                    detected_elements['name'] = value
                elif key == 'surname':
                    if detected_elements['name']:
                        detected_elements['name'] = f"{value} {detected_elements['name']}"
                    else:
                        detected_elements['name'] = value
                elif key == 'passport_number' and not detected_elements['passport_number']:
                    detected_elements['passport_number'] = value
                elif key == 'birthdate' and not detected_elements['birthdate']:
                    detected_elements['birthdate'] = value
                
                # Für jede MRZ-Information (außer mrz_lines), füge sie zu den sensiblen Regionen hinzu
                for line in text.split('\n'):
                    if value in line:
                        start_pos = text.find(line)
                        if start_pos != -1:
                            detected_elements['sensitive_regions'].append(
                                (start_pos, start_pos + len(line), line)
                            )
    
    return detected_elements

def parse_passport_mrz(mrz_lines):
    """
    Analysiert die MRZ-Zeilen eines Reisepasses und extrahiert sensible Informationen.
    
    MRZ im Reisepass besteht typischerweise aus zwei oder drei Zeilen mit 44 Zeichen:
    Zeile 1: Dokumententyp, Ausstellerland, Name
    Zeile 2: Passnummer, Nationalität, Geburtsdatum, Geschlecht, Gültigkeitsdatum, Personennummer
    
    Args:
        mrz_lines: Liste der erkannten MRZ-Zeilen
        
    Returns:
        Dictionary mit extrahierten sensiblen Informationen
    """
    if not mrz_lines or len(mrz_lines) < 1:
        return {}
    
    parsed_info = {
        'name': "",
        'surname': "",
        'passport_number': "",
        'nationality': "",
        'birthdate': "",
        'gender': "",
        'expiry_date': "",
        'personal_number': ""
    }
    
    # Standardisiere MRZ-Zeilen (entferne Leerzeichen, normalisiere Länge)
    cleaned_lines = [line.replace(" ", "").strip() for line in mrz_lines]
    
    # Sortiere nach Länge (die längsten sind wahrscheinlich die echten MRZ-Zeilen)
    cleaned_lines.sort(key=len, reverse=True)
    
    # Wir erwarten 2-3 Zeilen mit je etwa 44 Zeichen
    valid_mrz_lines = [line for line in cleaned_lines if len(line) >= 30]
    
    if len(valid_mrz_lines) >= 1:
        # Analysiere die erste Zeile (enthält oft Dokumententyp und Namen)
        first_line = valid_mrz_lines[0]
        
        # Name extrahieren (in der ersten Zeile, nach den ersten Zeichen)
        if len(first_line) > 5 and '<<' in first_line:
            name_part = first_line[5:]  # Skip "P<XXX" am Anfang
            name_parts = name_part.split('<<')
            
            if len(name_parts) >= 2:
                parsed_info['surname'] = name_parts[0].replace('<', ' ').strip()
                parsed_info['name'] = name_parts[1].replace('<', ' ').strip()
                print(f"MRZ-Name erkannt: {parsed_info['name']} {parsed_info['surname']}")
    
    if len(valid_mrz_lines) >= 2:
        # Analysiere die zweite Zeile (enthält oft Passnummer und Geburtsdatum)
        second_line = valid_mrz_lines[1]
        
        # Passnummer ist typischerweise die ersten 9 Zeichen
        if len(second_line) >= 9:
            passport_num = second_line[:9].replace('<', '')
            if passport_num and not passport_num.isalpha():  # Sicherstellen, dass es nicht nur Buchstaben sind
                parsed_info['passport_number'] = passport_num
                print(f"MRZ-Passnummer erkannt: {parsed_info['passport_number']}")
        
        # Geburtsdatum ist oft an Position 13-19 (Format: YYMMDD)
        if len(second_line) >= 19:
            birthdate = second_line[13:19]
            if birthdate.isdigit():
                try:
                    year = int(birthdate[:2])
                    month = int(birthdate[2:4])
                    day = int(birthdate[4:6])
                    
                    # Jahr korrigieren (19xx oder 20xx)
                    if year < 50:  # Heuristik: Wenn Jahr < 50, dann 20xx, sonst 19xx
                        year += 2000
                    else:
                        year += 1900
                    
                    if 1 <= month <= 12 and 1 <= day <= 31:
                        parsed_info['birthdate'] = f"{day:02d}.{month:02d}.{year}"
                        print(f"MRZ-Geburtsdatum erkannt: {parsed_info['birthdate']}")
                except ValueError:
                    pass
        
        # Geschlecht ist oft an Position 20 (M oder F)
        if len(second_line) >= 20:
            gender = second_line[20]
            if gender in ['M', 'F']:
                parsed_info['gender'] = 'Männlich' if gender == 'M' else 'Weiblich'
                print(f"MRZ-Geschlecht erkannt: {parsed_info['gender']}")
        
        # Ablaufdatum ist oft an Position 21-27 (Format: YYMMDD)
        if len(second_line) >= 27:
            expiry_date = second_line[21:27]
            if expiry_date.isdigit():
                try:
                    year = int(expiry_date[:2])
                    month = int(expiry_date[2:4])
                    day = int(expiry_date[4:6])
                    
                    # Jahr korrigieren (20xx standardmäßig, da Pässe nicht mehr als 10 Jahre gültig sind)
                    year += 2000
                    
                    if 1 <= month <= 12 and 1 <= day <= 31:
                        parsed_info['expiry_date'] = f"{day:02d}.{month:02d}.{year}"
                        print(f"MRZ-Ablaufdatum erkannt: {parsed_info['expiry_date']}")
                except ValueError:
                    pass
    
    return parsed_info

# --- Hauptausführung des Skripts ---
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Anonymisiere sensible Daten in Dokumenten')
    parser.add_argument('--input', '-i', type=str, default=r"C:\Users\haida\Documents\Python Scripts\OCR-Paddle\Screenshot 2025-06-13 011733.png", 
                        help='Pfad zur Eingabedatei')
    parser.add_argument('--output', '-o', type=str, default="dokument_anonymisiert.png", 
                        help='Pfad zur Ausgabedatei')    
    parser.add_argument('--model', '-m', type=str, default="qwen2.5vl:3b", 
                        help='Ollama-Modell für LLM-Verifikation')
    parser.add_argument('--rules', '-r', type=str, default="sensitive_data_rules.txt", 
                        help='Pfad zur Regeldatei für sensible Daten')
    parser.add_argument('--nollm', action='store_true', 
                        help='Deaktiviert LLM-Verifikation')
    parser.add_argument('--ollama-url', type=str, default="http://localhost:11434", 
                        help='URL des Ollama-Servers (Standard: http://localhost:11434)')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Aktiviert Debug-Modus mit detaillierten Ausgaben')
    parser.add_argument('--passport', '-p', action='store_true',
                        help='Hinweis, dass es sich um einen Pass/Ausweis handelt (verbessert die Erkennung)')    
    args = parser.parse_args()
    
    input_file = args.input
    output_file = args.output
    ollama_model = args.model
    rules_file = args.rules
    use_llm = not args.nollm
    debug_mode = args.debug
    is_passport = args.passport
    ollama_url = args.ollama_url
    
    if not os.path.exists(input_file):
        print(f"Fehler: Die Datei '{input_file}' wurde nicht gefunden.")
    else:
        print(f"Verwende Regeldatei: {rules_file}")
        print(f"LLM-Verifikation: {'Deaktiviert' if not use_llm else f'Aktiviert mit Modell {ollama_model}'}")
        if is_passport:
            print("Pass-/Ausweismodus aktiviert: Spezialisierte Erkennung wird verwendet")        
        if debug_mode:
            print("Debug-Modus aktiviert: Ausführliche Informationen werden angezeigt")
        
        # Erweiterte Parameter-Übergabe für die neuen Funktionen
        anonymize_document(
            image_path=input_file, 
            output_path=output_file, 
            use_llm=use_llm, 
            ollama_model=ollama_model,
            config_file=rules_file,
            debug_mode=debug_mode,
            is_passport=is_passport
        )


