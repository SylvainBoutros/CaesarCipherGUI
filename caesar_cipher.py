import string
from tkinter import *
from tkinter import ttk

class CaesarCipher:
    def __init__(self, root):
        self.root = root
        root.title("Caesar Cipher")
        root.geometry("750x750")
        root.resizable(0, 0)
        self.minmax = [x for x in range(0, 26)]

        self.main_frame = ttk.Frame(root, padding=5)
        self.main_frame.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.fonts = ("Arial", 16)

        self.encrypt_label = Label(self.main_frame, text="Encrypt Message:", font=self.fonts)
        self.encrypt_label.grid(column=0, row=0, sticky="nsew")

        self.encrypt_display = Text(self.main_frame, font=self.fonts, height=10, width=5)
        self.encrypt_display.grid(column=0, row=1, sticky="nsew")

        self.key_label = Label(self.main_frame, text="Key:", font=self.fonts)
        self.key_label.grid(column=6, row=0)

        self.key = Spinbox(self.main_frame, font=self.fonts, values=self.minmax)
        self.key.grid(column=6, row=1)

        self.decrypt_label = Label(self.main_frame, text="Decrypt Message:", font=self.fonts)
        self.decrypt_label.grid(column=7, row=0, sticky="nsew")

        self.decrypt_display = Text(self.main_frame, font=self.fonts, height=10, width=5)
        self.decrypt_display.grid(column=7, row=1, sticky="nsew")

        self.btn_encrypt = Button(self.main_frame, text="Encrypt", font=self.fonts, command=lambda: self.get_message("encrypt"))
        self.btn_encrypt.grid(column=0, row=2, columnspan=12, sticky="nsew")

        self.btn_decrypt = Button(self.main_frame, text="Decrypt", font=self.fonts, command=lambda: self.get_message("decrypt"))
        self.btn_decrypt.grid(column=0, row=3, columnspan=12, sticky="nsew")

        self.btn_clear = Button(self.main_frame, text="Clear Screen", font=self.fonts, command=self.clear_screen)
        self.btn_clear.grid(column=0, row=4, columnspan=12, sticky="nsew")

        self.btn_quit = Button(self.main_frame, text="Exit", font=self.fonts, command=self.safely_exit)
        self.btn_quit.grid(column=0, row=9, columnspan=12, sticky="nsew")

        self.types = None
        self.results = ""
        self.message = ""
        self.secret_key = 0
        self.alphabet = string.ascii_lowercase

    def get_message(self, types):
        self.secret_key = int(self.key.get())
        self.types = types

        if self.types == "encrypt":
            self.message = self.encrypt_display.get('1.0', 'end-1c')
            self.message = self.message.lower()
            self.results = self.do_magic()
            self.decrypt_display.insert('1.0', self.results)
            return
        self.message = self.decrypt_display.get('1.0', 'end-1c')
        self.message = self.message.lower()
        self.results = self.do_magic()
        self.encrypt_display.insert('1.0', self.results)
        return

    def do_magic(self):
        results = ''
        for letter in self.message:
            if letter in self.alphabet:
                letter_index = self.alphabet.find(letter)

                if self.types == "encrypt":
                    shifted_index = letter_index + self.secret_key
                elif self.types == "decrypt":
                    shifted_index = letter_index - self.secret_key

                if shifted_index >= len(self.alphabet):
                    shifted_index -= len(self.alphabet)
                elif shifted_index < 0:
                    shifted_index += len(self.alphabet)

                results = results + self.alphabet[shifted_index]
            else:
                results = results + letter
        return results

    def clear_screen(self):
        self.decrypt_display.delete('1.0', END)
        self.encrypt_display.delete('1.0', END)
        self.key.delete(0, 'end')
        self.key.insert(0, 0)
        self.message = ""

    def safely_exit(self):
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    root = Tk()
    cipher = CaesarCipher(root)
    cipher.run()
