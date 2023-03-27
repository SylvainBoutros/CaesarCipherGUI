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

        # The label saying "Encrypt Message" will be starting at column 0 and row 0, having a column span of 12
        self.encrypt_label = Label(self.main_frame, text="Encrypt Message:", font=self.fonts)
        self.encrypt_label.grid(column=0, row=0, sticky="nsew")

        # The encrypt display where we can type a message in plain text should start at column 0 and row 1
        # It will have a height of 5 and a width of 12
        self.encrypt_display = Text(self.main_frame, font=self.fonts, height=5, width=40)
        self.encrypt_display.grid(column=0, row=1, columnspan=12)#, sticky="nsew")

        # The label saying "Decrypt Messgae" will be starting at column 0 and row 6, having a column span of 12 as well
        self.decrypt_label = Label(self.main_frame, text="Decrypt Message:", font=self.fonts)
        self.decrypt_label.grid(column=0, row=6, sticky="nsew")

        # The decrypt display where we can paste a message that was 'encrypted' should start at column 0 and row 7 
        # It will have a height of 5 and width of 12
        self.decrypt_display = Text(self.main_frame, font=self.fonts, height=5, width=40)
        self.decrypt_display.grid(column=0, row=7, columnspan=12)#, sticky="nsew")
        
        # The secret key label will be starting at column 0 and row 12, having a column span of half the display 6
        self.key_label = Label(self.main_frame, text="Key:", font=self.fonts)
        self.key_label.grid(column=0, row=12, columnspan=6)

        # The spinbox where we can adjust the number for the secret key will be taking the remaining half of that display
        self.key = Spinbox(self.main_frame, font=self.fonts, values=self.minmax)
        self.key.grid(column=6, row=12, columnspan=6)

        # The encrypt button will be starting on column 0 and row 13
        self.btn_encrypt = Button(self.main_frame, text="Encrypt", font=self.fonts, command=lambda: self.get_message("encrypt"))
        self.btn_encrypt.grid(column=0, row=13, columnspan=6, sticky="nsew")

        # The decrypt button will be starting on column 6 and row 13
        self.btn_decrypt = Button(self.main_frame, text="Decrypt", font=self.fonts, command=lambda: self.get_message("decrypt"))
        self.btn_decrypt.grid(column=6, row=13, columnspan=6, sticky="nsew")

        # The clear button will be starting on column 0 and row 14
        self.btn_clear = Button(self.main_frame, text="Clear Screen", font=self.fonts, command=self.clear_screen)
        self.btn_clear.grid(column=0, row=14, columnspan=6, sticky="nsew")
        
        # The quit button will be starting on column 6 and row 14
        self.btn_quit = Button(self.main_frame, text="Exit", bg="red", font=self.fonts, command=self.safely_exit)
        self.btn_quit.grid(column=6, row=14, columnspan=6, sticky="nsew")

        self.types = None
        self.results = ""
        self.message = ""
        self.secret_key = 0
        self.alphabet = string.ascii_lowercase

    def get_message(self, types):
        secret_key = int(self.key.get())
        self.types = types
        
        main_msg_display = self.encrypt_display if self.types == "encrypt" else self.decrypt_display
        secondary_msg_display = self.decrypt_display if self.types == "encrypt" else self.encrypt_display

        msg = main_msg_display.get('1.0', 'end-1c').lower()
        results = self.do_magic(msg, secret_key)

        main_msg_display.delete('1.0', END)
        secondary_msg_display.delete('1.0', END)
        secondary_msg_display.insert('1.0', results)

    def do_magic(self, message, s_key):
        results = ''
        for letter in message:
            if letter in self.alphabet:
                letter_index = self.alphabet.find(letter)

                if self.types == "encrypt":
                    shifted_index = letter_index + s_key
                elif self.types == "decrypt":
                    shifted_index = letter_index - s_key

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
