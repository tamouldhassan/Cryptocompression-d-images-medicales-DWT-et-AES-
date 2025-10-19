import socket
import cv2
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import threading
from Crypto.Cipher import AES
import zlib
import io


class ImageDecryptionServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Serveur de Déchiffrement d'Images")
        self.root.geometry("900x700")

        # Variables
        self.server_socket = None
        self.is_server_running = False
        self.encrypted_data = None
        self.metadata = None
        self.decrypted_image = None
        self.original_image = None
        self.key = b'MasterSIDI2025__'

        self.setup_ui()

    def setup_ui(self):
        # Créer un canvas principal avec scrollbar
        self.main_canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
        )

        self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)

        # Bind mousewheel to canvas
        def _on_mousewheel(event):
            self.main_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self.main_canvas.bind("<MouseWheel>", _on_mousewheel)

        # Pack canvas and scrollbar
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Frame principal dans le frame scrollable
        main_frame = ttk.Frame(self.scrollable_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configuration du serveur
        server_frame = ttk.LabelFrame(main_frame, text="Configuration du Serveur", padding="10")
        server_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(server_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_var = tk.StringVar(value="192.168.96.2")
        ttk.Entry(server_frame, textvariable=self.ip_var, width=15).grid(row=0, column=1, padx=(5, 10))

        ttk.Label(server_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        self.port_var = tk.StringVar(value="5050")
        ttk.Entry(server_frame, textvariable=self.port_var, width=10).grid(row=0, column=3, padx=(5, 10))

        self.start_btn = ttk.Button(server_frame, text="Démarrer Serveur", command=self.start_server)
        self.start_btn.grid(row=0, column=4, padx=(10, 0))

        self.stop_btn = ttk.Button(server_frame, text="Arrêter Serveur", command=self.stop_server, state="disabled")
        self.stop_btn.grid(row=0, column=5, padx=(5, 0))

        # Status
        self.status_var = tk.StringVar(value="Serveur arrêté")
        ttk.Label(server_frame, textvariable=self.status_var, foreground="red").grid(row=1, column=0, columnspan=6,
                                                                                     pady=(10, 0))

        # Frame pour les images
        image_frame = ttk.Frame(main_frame)
        image_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Image chiffrée
        encrypted_frame = ttk.LabelFrame(image_frame, text="Image Reçue (Chiffrée)", padding="10")
        encrypted_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))

        self.encrypted_canvas = tk.Canvas(encrypted_frame, width=300, height=200, bg="white", bd=0,
                                          highlightthickness=0)
        self.encrypted_canvas.pack(padx=0, pady=2)

        self.decrypt_btn = ttk.Button(encrypted_frame, text="Déchiffrer", command=self.decrypt_image, state="disabled")
        self.decrypt_btn.pack(pady=5)

        # Image déchiffrée
        decrypted_frame = ttk.LabelFrame(image_frame, text="Image Déchiffrée", padding="10")
        decrypted_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))

        self.decrypted_canvas = tk.Canvas(decrypted_frame, width=300, height=200, bg="white", bd=0,
                                          highlightthickness=0)
        self.decrypted_canvas.pack(padx=0, pady=2)

        self.decompress_btn = ttk.Button(decrypted_frame, text="Décompresser", command=self.decompress_image,
                                         state="disabled")
        self.decompress_btn.pack(pady=5)

        # Image décompressée (nouvelle section)
        decompressed_frame = ttk.LabelFrame(main_frame, text="Image Décompressée", padding="5")
        decompressed_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        self.decompressed_canvas = tk.Canvas(decompressed_frame, width=620, height=250, bg="white", bd=0,
                                             highlightthickness=0)
        self.decompressed_canvas.pack(padx=0, pady=0)

        # Image originale
        original_frame = ttk.LabelFrame(main_frame, text="Image Originale", padding="5")
        original_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        self.original_canvas = tk.Canvas(original_frame, width=620, height=250, bg="white", bd=0, highlightthickness=0)
        self.original_canvas.pack(padx=0, pady=0)

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="10")
        log_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        self.log_text = tk.Text(log_frame, height=8, width=80)
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")

        # Configuration des poids pour le redimensionnement
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        image_frame.columnconfigure(0, weight=1)
        image_frame.columnconfigure(1, weight=1)
        image_frame.rowconfigure(0, weight=1)

    def log_message(self, message):
        """Ajouter un message au log"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def start_server(self):
        """Démarrer le serveur dans un thread séparé"""
        if not self.is_server_running:
            self.is_server_running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.status_var.set("Serveur en cours de démarrage...")

            server_thread = threading.Thread(target=self._run_server, daemon=True)
            server_thread.start()

    def stop_server(self):
        """Arrêter le serveur"""
        self.is_server_running = False
        if self.server_socket:
            self.server_socket.close()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Serveur arrêté")
        self.log_message("Serveur arrêté")

    def _run_server(self):
        """Fonction principale du serveur"""
        try:
            host = self.ip_var.get()
            port = int(self.port_var.get())

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(1)

            self.root.after(0, lambda: self.status_var.set(f"Serveur en écoute sur {host}:{port}"))
            self.root.after(0, lambda: self.log_message(f"Serveur démarré sur {host}:{port}"))

            while self.is_server_running:
                try:
                    self.server_socket.settimeout(1.0)
                    conn, addr = self.server_socket.accept()
                    self.root.after(0, lambda: self.log_message(f"Connexion établie avec {addr}"))

                    with conn:
                        self._handle_client(conn)

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_server_running:
                        self.root.after(0, lambda: self.log_message(f"Erreur de connexion: {str(e)}"))

        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"Erreur serveur: {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Erreur", f"Erreur serveur: {str(e)}"))
        finally:
            if self.server_socket:
                self.server_socket.close()

    def _handle_client(self, conn):
        """Gérer la communication avec le client"""
        try:
            # Recevoir la longueur des métadonnées
            meta_len_bytes = conn.recv(4)
            if not meta_len_bytes:
                return
            meta_len = int.from_bytes(meta_len_bytes, 'big')

            # Recevoir les métadonnées
            meta_data = b''
            while len(meta_data) < meta_len:
                chunk = conn.recv(meta_len - len(meta_data))
                if not chunk:
                    raise ConnectionError("Réception des métadonnées interrompue")
                meta_data += chunk

            # Parser les métadonnées
            meta = meta_data.decode()
            shape_h, shape_w, pad_h, pad_w, mode, iv = meta.split(',')
            self.metadata = {
                'shape': (int(shape_h), int(shape_w)),
                'pad': (int(pad_h), int(pad_w)),
                'mode': mode,
                'iv_or_nonce': bytes.fromhex(iv)
            }

            # Recevoir les données chiffrées
            data_len = int.from_bytes(conn.recv(4), 'big')
            self.encrypted_data = b''
            while len(self.encrypted_data) < data_len:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                self.encrypted_data += chunk

            self.root.after(0, lambda: self.log_message(f"Données reçues ({len(self.encrypted_data)} octets)"))
            self.root.after(0, lambda: self._display_encrypted_placeholder())

            # Traitement automatique : déchiffrement seulement
            self.root.after(0, lambda: self._auto_decrypt_only())

        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"Erreur lors de la réception: {str(e)}"))

    def _display_encrypted_placeholder(self):
        """Afficher un placeholder pour l'image chiffrée"""
        self.encrypted_canvas.delete("all")
        self.encrypted_canvas.create_rectangle(50, 50, 250, 150, fill="gray", outline="black")
        self.encrypted_canvas.create_text(150, 100, text="Image Chiffrée\nReçue", fill="white", font=("Arial", 12))

    def _auto_decrypt_only(self):
        """Déchiffrement automatique seulement"""
        try:
            if not self.encrypted_data or not self.metadata:
                self.log_message("Erreur: Aucune donnée chiffrée disponible")
                return

            # Étape 1: Déchiffrement
            self.log_message("Déchiffrement automatique en cours...")

            self.decrypted_image = self._decrypt_aes(
                self.encrypted_data,
                self.key,
                self.metadata['iv_or_nonce'],
                self.metadata['shape'],
                self.metadata['mode'],
                self.metadata['pad']
            )

            # Afficher l'image déchiffrée
            self._display_image_on_canvas(self.decrypted_image, self.decrypted_canvas)
            self.log_message("✓ Image déchiffrée avec succès")

            # Activer les boutons pour un traitement manuel
            self.decrypt_btn.config(state="normal")
            self.decompress_btn.config(state="normal")

        except Exception as e:
            self.log_message(f"Erreur lors du déchiffrement automatique: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur lors du déchiffrement: {str(e)}")
            # Activer le bouton de déchiffrement manuel en cas d'erreur
            self.decrypt_btn.config(state="normal")

    def decrypt_image(self):
        """Déchiffrer l'image reçue (mode manuel)"""
        try:
            if not self.encrypted_data or not self.metadata:
                messagebox.showerror("Erreur", "Aucune donnée chiffrée disponible")
                return

            self.log_message("Déchiffrement manuel en cours...")

            # Déchiffrer les données
            self.decrypted_image = self._decrypt_aes(
                self.encrypted_data,
                self.key,
                self.metadata['iv_or_nonce'],
                self.metadata['shape'],
                self.metadata['mode'],
                self.metadata['pad']
            )

            # Afficher l'image déchiffrée
            self._display_image_on_canvas(self.decrypted_image, self.decrypted_canvas)
            self.log_message("Image déchiffrée avec succès (mode manuel)")
            self.decompress_btn.config(state="normal")

        except Exception as e:
            self.log_message(f"Erreur lors du déchiffrement manuel: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur lors du déchiffrement: {str(e)}")

    def decompress_image(self):
        """Décompresser l'image pour obtenir l'image originale (mode manuel)"""
        try:
            if self.decrypted_image is None:
                messagebox.showerror("Erreur", "Aucune image déchiffrée disponible")
                return

            self.log_message("Décompression manuelle en cours...")

            # Essayer différentes méthodes de décompression
            decompression_success = False

            try:
                # Méthode 1: Décompression zlib directe
                self.log_message("Tentative de décompression zlib...")
                compressed_data = self.decrypted_image.tobytes()
                decompressed_data = zlib.decompress(compressed_data)
                image_array = np.frombuffer(decompressed_data, dtype=np.uint8)
                self.original_image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

                if self.original_image is not None:
                    self.log_message("✓ Décompression zlib réussie")
                    decompression_success = True
                else:
                    raise ValueError("Échec du décodage image après décompression zlib")

            except Exception as e1:
                self.log_message(f"Décompression zlib échouée: {str(e1)}")
                try:
                    # Méthode 2: Essayer de décoder l'image déchiffrée comme données JPEG/PNG compressées
                    self.log_message("Tentative de décodage direct comme image compressée...")
                    # Convertir l'image déchiffrée en bytes
                    image_bytes = self.decrypted_image.tobytes()
                    # Essayer de décoder comme image
                    image_array = np.frombuffer(image_bytes, dtype=np.uint8)
                    self.original_image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

                    if self.original_image is not None:
                        self.log_message("✓ Décodage direct réussi")
                        decompression_success = True
                    else:
                        raise ValueError("Échec du décodage direct")

                except Exception as e2:
                    self.log_message(f"Décodage direct échoué: {str(e2)}")
                    try:
                        # Méthode 3: Utiliser l'image déchiffrée directement si elle semble valide
                        self.log_message("Utilisation de l'image déchiffrée comme image finale...")
                        if len(self.decrypted_image.shape) >= 2:
                            self.original_image = self.decrypted_image.copy()
                            # Convertir en couleur si c'est en niveaux de gris
                            if len(self.decrypted_image.shape) == 2:
                                self.original_image = cv2.cvtColor(self.original_image, cv2.COLOR_GRAY2BGR)
                            self.log_message("✓ Image déchiffrée utilisée directement")
                            decompression_success = True
                        else:
                            raise ValueError("Format d'image invalide")

                    except Exception as e3:
                        self.log_message(f"Toutes les méthodes de décompression ont échoué: {str(e3)}")
                        messagebox.showerror("Erreur",
                                             "Impossible de décompresser l'image avec toutes les méthodes disponibles")
                        return

            if decompression_success and self.original_image is not None:
                # Extraire seulement la bande LL (approximation basse fréquence)
                ll_band = self._extract_ll_band(self.original_image)

                # Afficher seulement la bande LL dans le canvas décompressé
                self._display_image_on_canvas(ll_band, self.decompressed_canvas, (600, 230))

                # Aussi l'afficher dans le canvas original pour compatibilité
                self._display_image_on_canvas(ll_band, self.original_canvas, (600, 230))

                self.log_message("✓ Image décompressée - Bande LL extraite et affichée")
                self.log_message(f"Dimensions de la bande LL: {ll_band.shape}")
                self.log_message(f"Dimensions de l'image originale: {self.original_image.shape}")
            else:
                messagebox.showerror("Erreur", "Échec de la décompression")

        except Exception as e:
            self.log_message(f"Erreur générale lors de la décompression: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur lors de la décompression: {str(e)}")

    def _display_image_on_canvas(self, cv_image, canvas, size=(280, 180)):
        """Afficher une image OpenCV sur un canvas Tkinter"""
        try:
            if cv_image is None:
                self.log_message("Erreur: Image None reçue pour affichage")
                return

            # Convertir BGR vers RGB si l'image est en couleur
            if len(cv_image.shape) == 3 and cv_image.shape[2] == 3:
                rgb_image = cv2.cvtColor(cv_image, cv2.COLOR_BGR2RGB)
            elif len(cv_image.shape) == 2:
                # Image en niveaux de gris
                rgb_image = cv_image
            else:
                rgb_image = cv_image

            # Redimensionner l'image pour l'affichage
            pil_image = Image.fromarray(rgb_image)

            # Calculer les dimensions en gardant le ratio
            img_width, img_height = pil_image.size
            canvas_width, canvas_height = size

            # Calculer le ratio pour garder les proportions
            ratio = min(canvas_width / img_width, canvas_height / img_height)
            new_width = int(img_width * ratio)
            new_height = int(img_height * ratio)

            pil_image = pil_image.resize((new_width, new_height), Image.Resampling.LANCZOS)

            # Convertir pour Tkinter
            tk_image = ImageTk.PhotoImage(pil_image)

            canvas.delete("all")
            canvas.create_image(canvas.winfo_width() // 2, canvas.winfo_height() // 2,
                                anchor=tk.CENTER, image=tk_image)

            # Garder une référence pour éviter la garbage collection
            canvas.image = tk_image

        except Exception as e:
            self.log_message(f"Erreur d'affichage: {str(e)}")

    def _extract_ll_band(self, image):
        """Extraire seulement la bande LL (approximation basse fréquence) de l'image"""
        try:
            # Si l'image est en couleur, la convertir en niveaux de gris
            if len(image.shape) == 3:
                gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            else:
                gray_image = image.copy()

            # Obtenir les dimensions de l'image
            height, width = gray_image.shape

            # La bande LL correspond généralement au quart supérieur gauche
            # dans une décomposition en ondelettes
            ll_height = height // 2
            ll_width = width // 2

            # Extraire la bande LL (coin supérieur gauche)
            ll_band = gray_image[:ll_height, :ll_width]

            # Convertir en image couleur pour l'affichage (BGR)
            ll_band_color = cv2.cvtColor(ll_band, cv2.COLOR_GRAY2BGR)

            return ll_band_color

        except Exception as e:
            self.log_message(f"Erreur lors de l'extraction de la bande LL: {str(e)}")
            # En cas d'erreur, retourner l'image originale
            return image

    def _unpad_image(self, image, pad):
        """Supprimer le padding d'une image"""
        pad_h, pad_w = pad
        return image[:-pad_h or None, :-pad_w or None]

    def _decrypt_aes(self, ciphertext, key, iv_or_nonce, shape, mode_name, pad):
        """Déchiffrer les données AES"""
        mode_dict = {
            "CBC": AES.MODE_CBC,
            "CFB": AES.MODE_CFB,
            "OFB": AES.MODE_OFB,
            "CTR": AES.MODE_CTR
        }

        mode = mode_dict[mode_name]
        if mode_name == "CTR":
            cipher = AES.new(key, mode, nonce=iv_or_nonce)
        else:
            cipher = AES.new(key, mode, iv=iv_or_nonce)

        decrypted_bytes = cipher.decrypt(ciphertext)
        padded_shape = (shape[0] + pad[0], shape[1] + pad[1])
        decrypted = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(padded_shape)
        return self._unpad_image(decrypted, pad)


def main():
    root = tk.Tk()
    app = ImageDecryptionServer(root)

    # Gérer la fermeture de l'application
    def on_closing():
        app.stop_server()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()