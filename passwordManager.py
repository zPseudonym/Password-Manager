# Imports all modules
from tkinter import *
import sqlite3, secrets, string, pyperclip, bcrypt
from tkinter import messagebox, ttk
from cryptography.fernet import Fernet
from os import path

# Sets all color variables
backgroundColor = "#282828"
colorWhite = "#FFF"
colorBlack = "#000"
buttonBackgroundColor = "#3a3b3c"
entryBackgroundColor = "#e4e6eb"

# Creates a new database for the master password if it does not exist yet
with sqlite3.connect("masterTresor.db") as db:
    cursor = db.cursor()
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS masterpassword(
                       id INTEGER PRIMARY KEY,
                       password TEXT NOT NULL);
                    """)
    
# Sets settings for the login window
loginWindow = Tk()
loginWindow.title("Login")
loginWindow.config(bg=backgroundColor)

# Hashes and salts the master password
def hashMasterPassword(password):
    #salt = b'$2b$05$oMRwuh5ztg2GWaibFvU8dO'
    salt = bcrypt.gensalt()
    password = password.encode("utf-8")
    hashedPassword = bcrypt.hashpw(password, salt)

    return hashedPassword.decode()

# Launches window for the first login, when the master password has not been created yet
def firstLogin():
    loginWindow.geometry("250x180")
    
    masterPasswordLabel = Label(loginWindow, text="Set master password", fg=colorWhite, bg=backgroundColor)
    masterPasswordLabel.config(anchor=CENTER)
    masterPasswordLabel.pack()
    
    masterPasswordEntry = Entry(loginWindow, width=20, show="*", bg=entryBackgroundColor, fg=colorBlack)
    masterPasswordEntry.pack()
    masterPasswordEntry.focus()
    
    masterPasswordConfirmLabel = Label(loginWindow, text="Confirm master password", fg=colorWhite, bg=backgroundColor)
    masterPasswordConfirmLabel.pack()
    
    masterPasswordConfirmEntry = Entry(loginWindow, show="*", bg=entryBackgroundColor, fg=colorBlack)
    masterPasswordConfirmEntry.pack()

    
    # Saves the hashed and salted master password
    def saveMasterPassword():
        if(masterPasswordEntry.get() == "" or masterPasswordConfirmEntry.get() == ""):
            pass
        elif(masterPasswordEntry.get() == masterPasswordConfirmEntry.get()):
            hashedPassword = hashMasterPassword(masterPasswordEntry.get())
            
            addMasterPassword = """INSERT INTO masterpassword(password) VALUES (?)"""
            cursor.execute(addMasterPassword, [(hashedPassword)])
            db.commit()
            
            passwordVault()
        
        else:
            messagebox.showerror("Error", "Passwords do not match!")
            
    saveMasterPasswordButton = Button(loginWindow, text="Save master password", command=saveMasterPassword, fg="black", bg=backgroundColor)
    saveMasterPasswordButton.pack(pady=20)
    
# Launches window for the regular login (i.e. not first), when a master password already exists
def regularLogin():
    loginWindow.geometry("250x100")
    
    loginLabel = Label(loginWindow, text="Enter master password", fg=colorWhite, bg=backgroundColor)
    loginLabel.config(anchor=CENTER)
    loginLabel.pack()
    
    loginEntry = Entry(loginWindow, show="*", bg=entryBackgroundColor, fg=colorBlack, insertbackground="black")
    loginEntry.pack()
    loginEntry.focus()
    
    def getMasterPasswordFromDB():
        checkHashedMasterPassword = hashMasterPassword(loginEntry.get())
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkHashedMasterPassword])
        
        return cursor.fetchall()
    
    # Checks if the entered master password is correct
    def checkMasterPassword():
        match = getMasterPasswordFromDB()

        if(match):
            passwordVault()
        else:
            loginEntry.delete(0, "end")
            messagebox.showerror("Error", "Password is not correct!")
            
    loginWithMasterPasswordButton = Button(loginWindow, text="log in", command=checkMasterPassword, fg=colorBlack, bg=backgroundColor)
    loginWithMasterPasswordButton.pack(pady=10)
    
# Starts the password manager
def passwordVault():
    loginWindow.destroy()
    startPasswordManager()
    
# Launches the first login window if master password does not exist in the database, otherwise launches the regular login window
cursor.execute("SELECT * FROM masterpassword")
if(cursor.fetchall()):
    regularLogin()
else:
    firstLogin()

def startPasswordManager():
    # Sets settings for the main window
    mainWindow = Tk()
    mainWindow.title("Password Manager")
    mainWindow.geometry("360x220")
    mainWindow.resizable(False, False)
    mainWindow.config(bg=backgroundColor)
    mainWindow.tk.call('wm', 'iconphoto', mainWindow._w, PhotoImage(file='images/icons/lock.png'))
    mainWindow.option_add( "*font", "Consolas 11" )

    # Checks if it is the first login to create a new key
    if(path.isfile("pwManager.db")):
        global fernet
        with open("key.key", "rb") as keyFile:
            keyFile.seek(0)
            key = keyFile.read()
            fernet = Fernet(key)
    else:
        with open("key.key", "wb") as keyFile:
                key = Fernet.generate_key()
                fernet = Fernet(key)
                keyFile.seek(0)
                keyFile.write(key)

    # Function for encrypting the password database
    def encryptPasswordDatabase():
        with open("pwManager.db", "rb") as passwordDatabase:
            data = passwordDatabase.read()
            data = fernet.encrypt(data)
            with open("pwManager.db", "wb") as passwordDatabase:
                passwordDatabase.write(data)

    # Function for decrypting the password database
    def decryptPasswordDatabase():
        with open("pwManager.db", "rb") as passwordDatabase:
            data = passwordDatabase.read()
            try:
                data = fernet.decrypt(data)
            except:
                pass
            with open("pwManager.db", "wb") as passwordDatabase:
                passwordDatabase.write(data)

    # Checks if the password database already exists
    if(path.exists("pwManager.db")):
        pass

    # Creates a new password database if it does not exist yet
    else:
        conn = sqlite3.connect("pwManager.db")
        cursor = conn.cursor()
        cursor.execute(""" CREATE TABLE IF NOT EXISTS pwManager (
                                appName text,
                                username text,
                                url text,
                                password text
                                )""")

        # Saves the changes in the database and closes the database connection
        conn.commit()
        conn.close()
        # Encrypts the database
        encryptPasswordDatabase()

    # Function for the password generator
    def passwordGeneratorWindow():
        passGen = Toplevel()
        passGen.attributes("-topmost", True)
        passGen.focus()
        passGen.resizable(width=False, height=False)
        passGen.title("Password Generator")
        passGen.config(bg=backgroundColor)
        
        # Checks which password options have been selected
        def checkPasswordGeneratorOptions():
            global checkNonCapitalLetters
            global checkCapitalLetters
            global checkNumbers
            global checkSymbols
            checkNonCapitalLetters = varNonCapitalLetters.get()
            checkCapitalLetters = varCapitalLetters.get()
            checkNumbers = varNumbers.get()
            checkSymbols = varSymbols.get()
            
        # Assigns the password length to a global variable
        def gebeLaengeAn(laenge):
            global passwordLength
            passwordLength = laenge
            
        # Function for generating a password according to the specified password parameters
        def createPassword():
            generatedPasswordField.delete(0, END)
            counter = 0
            selectionList = []
            password = ""
            global passwordLength

            # Checks which password options have been selected and adds them to the selectionList array
            try:
                if checkNonCapitalLetters == 1:
                    counter += 1
                    selectionList.append("nonCapitalLetters")
            except:
                pass
            try:
                if checkCapitalLetters == 1:
                    counter += 1
                    selectionList.append("capitalLetters")
            except:
                pass
            try:
                if checkNumbers == 1:
                    counter += 1
                    selectionList.append("numbers")
            except:
                pass
            try:
                if checkSymbols == 1:
                    counter += 1
                    selectionList.append("symbols")
            except:
                pass

            # Generates a password, if at least one parameter has been checked
            if counter !=0:
                try:
                    length = int(passwordLength)
                except:
                    length = 8
                while length > 0:
                    if "nonCapitalLetters" in selectionList:
                        password += secrets.choice(nonCapitalLettersCharacters)
                        length -= 1
                    if "capitalLetters" in selectionList:
                        password += secrets.choice(capitalLettersCharacters)
                        length -= 1
                    if "numbers" in selectionList:
                        password += secrets.choice(numberCharacters)
                        length -= 1
                    if "symbols" in selectionList:
                        password += secrets.choice(symbolCharacters)
                        length -= 1

            # Outputs an error message, if none of the four options have been selected
            else:
                messagebox.showerror("Error", "At least one option has to be selected!")
                passGen.lift()
                passGen.focus()
                
            # Shuffles all values in the array to make them "random"
            passwordArrayNonShuffled = list(password)
            passwordArrayShuffled = []
            while len(passwordArrayNonShuffled) > 0:
                pickedCharacter = secrets.choice(passwordArrayNonShuffled)
                passwordArrayShuffled.append(pickedCharacter)
                passwordArrayNonShuffled.remove(pickedCharacter)
            password = ''.join(passwordArrayShuffled)
            generatedPasswordField.config(state=NORMAL)
            generatedPasswordField.delete(0, END)
            generatedPasswordField.insert(END, password)
            generatedPasswordField.config(state=DISABLED)
            
        # Function for copying the generated password to the clipboard
        def copyGeneratedPassword():
            copiedPassword = generatedPasswordField.get()
            pyperclip.copy(copiedPassword)
            
        # Function for closing the password generator when cancel button is clicked
        def cancelPasswordGenerator():
            passGen.destroy()
            
        # Function for closing the password generator window after creating a password
        def confirmPassword():
            manualPasswordSelected = False
            if(generatedPasswordField.get()!=""):
                passwordEntryField.config(state=NORMAL)
                passwordEntryField.delete(0, END)
                passwordEntryField.insert(END, generatedPasswordField.get())
                passwordEntryField.config(state=DISABLED)
                passGen.destroy()
                
            else:
                messagebox.showerror("Error", "No password selected!")
                passGen.lift()
                passGen.focus()

        # Sets variables for all characters
        nonCapitalLettersCharacters = list(string.ascii_lowercase)
        capitalLettersCharacters = list(string.ascii_uppercase)
        numberCharacters = list(string.digits)
        symbolCharacters = list(string.punctuation)

        # Creates label and entry field for the password generator
        passwordGeneratorLabel = Label(passGen, text="Password: ", fg=colorWhite, bg=backgroundColor)
        passwordGeneratorLabel.grid(row=0, padx=10)
        generatedPasswordField = Entry(passGen, state=DISABLED, bg=entryBackgroundColor, fg="white")
        generatedPasswordField.grid(row=0, column=1)
        
        varNonCapitalLetters = IntVar()
        varCapitalLetters = IntVar()
        varNumbers = IntVar()
        varSymbols = IntVar()

        # Creates checkbuttons for selecting the password parameters
        Checkbutton(passGen, text="Non-capital letters (abc)", variable=varNonCapitalLetters, command=checkPasswordGeneratorOptions, fg=colorWhite, bg=backgroundColor, selectcolor=buttonBackgroundColor).grid(row=2, column=0)
        Checkbutton(passGen, text="Capitals letters (ABC)", variable=varCapitalLetters, command=checkPasswordGeneratorOptions, fg=colorWhite, bg=backgroundColor, selectcolor=buttonBackgroundColor).grid(sticky="w", row=3, column=0)
        Checkbutton(passGen, text="Numbers (123)", variable=varNumbers, command=checkPasswordGeneratorOptions, fg=colorWhite, bg=backgroundColor, selectcolor=buttonBackgroundColor).grid(row=2, column=1)
        Checkbutton(passGen, text="Symbols (#$&)", variable=varSymbols, command=checkPasswordGeneratorOptions, fg=colorWhite, bg=backgroundColor, selectcolor=buttonBackgroundColor).grid(row=3, column=1)

        # Creates label to display the text for the password length
        generatedPasswordLengthLabel = Label(passGen, text="Password length:", fg=colorWhite, bg=backgroundColor)
        generatedPasswordLengthLabel.grid(row=1, column=0, padx=10)
            
        # Creates scale from 8 to 30 for selecting the password length
        passwordLengthScale = Scale(passGen, from_=8, to=30, orient=HORIZONTAL, command=gebeLaengeAn, fg=colorWhite, bg=backgroundColor, activebackground=backgroundColor, highlightbackground=backgroundColor)
        passwordLengthScale.grid(row=1, column=1)

        # Creates the text and frame in the password generator
        passwordTipFrame = Frame(passGen, bg="#efebdc", bd=2)
        passwordTipFrame.grid(row=1, column=2, rowspan=3)
        passwordTip = Label(passwordTipFrame, text="Make sure to use \ndifferent passwords \nfor different accounts!", fg=colorWhite, bg=backgroundColor)
        passwordTip.grid(row=0, column=0, rowspan=3)

        # Creates button for copying the password to the clipboard
        copyPasswordButton = Button(passGen, text="Copy password", command=copyGeneratedPassword, fg=colorBlack, bg=backgroundColor)
        copyPasswordButton.grid(row=0, column=2, padx=10, pady=10)

        # Creates button for generating a password
        generatePasswordButton = Button(passGen, text="Generate password", command=createPassword, fg=colorBlack, bg=backgroundColor)
        generatePasswordButton.grid(row=6, column=0)

        # Creates button for canceling password creation
        cancelPasswordCreationButton = Button(passGen, text="Cancel", command=cancelPasswordGenerator, fg=colorBlack, bg=backgroundColor)
        cancelPasswordCreationButton.grid(row=6, column=2)

        # Creates button for confirming the password
        confirmPasswordButton = Button(passGen, text="Confirm password", command=confirmPassword, fg=colorBlack, bg=backgroundColor)
        confirmPasswordButton.grid(row=6, column=1, pady=10)

    # Function for checking if password should be set manually or generated
    def checkPasswordManualGenerated():
        if getRadiobuttonValue.get() == "A":
            passwordEntryField.delete(0, END)
            passwordEntryField.config(state=DISABLED)
            launchPasswordGenerator.config(state=NORMAL)
            
        else:
            passwordEntryField.config(state=NORMAL)
            passwordEntryField.delete(0, END)
            launchPasswordGenerator.config(state=DISABLED)

    # Function for adding a record to the password database
    def addRecordToDatabase():
        # Decrypts the database
        decryptPasswordDatabase()
        # Establishes a connection to the database and create a cursor
        conn = sqlite3.connect("pwManager.db")
        cursor = conn.cursor()

        # Adds the password, if all mandatory fields have been filled
        if nameEntryField.get()!= "" and usernameEntryField.get()!= "" and passwordEntryField.get()!= "":
            cursor.execute("INSERT INTO pwManager VALUES(:nameEntryField, :usernameEntryField, :urlEntryField, :passwordEntryField)",

            {
            'nameEntryField': nameEntryField.get(),
            'usernameEntryField': usernameEntryField.get(),
            'urlEntryField': urlEntryField.get(),
            'passwordEntryField': passwordEntryField.get()
            })

            # Saves the changes in the database and closes the database connection
            conn.commit()
            conn.close()
            # Encrypts the database
            encryptPasswordDatabase()

            # Displays an information message and resets all buttons and other fields
            messagebox.showinfo("Information", "Added record!")
            manualRadiobutton.select()
            launchPasswordGenerator.config(state="disabled")
            nameEntryField.delete(0, END)
            urlEntryField.delete(0, END)
            usernameEntryField.delete(0, END)
            passwordEntryField.config(state=NORMAL)
            passwordEntryField.delete(0, END)
            showRecords(3)

        # Displays an error message, if not all mandatory fields have been filled
        else:
            messagebox.showerror("Error", "Incomplete values!")
            # Closes the database
            conn.close()
            # Encrypts the database
            encryptPasswordDatabase()

    # Function for deleting a record from the database 
    def deleteRecordFromDatabase():
        deleteRecordID = deleteRecordEntryField.get()
        # Checks if an ID has been specified
        if(deleteRecordID!=""):
            # Checks if the specified ID exists in the database
            try:
                # Decrypts the database
                decryptPasswordDatabase()
                # Establishes a connection to the database and create a cursor
                conn = sqlite3.connect("pwManager.db")
                cursor = conn.cursor()
                
                cursor.execute("Select appName from pwManager where oid = " +deleteRecordID)
                pruefeObZeileExistiert = cursor.fetchall()
                nameEntryField.insert(END, pruefeObZeileExistiert)
            
                # Displays an error if record ID does not exist in the database
                if(nameEntryField.get()==""):
                    messagebox.showerror("Error", "ID not found!")
                    deleteRecordEntryField.config(state=NORMAL)
                    editRecordEntryField.config(state=NORMAL)
                    
                    # Saves the changes in the database and closes the database connection
                    conn.commit()
                    conn.close()
                    # Encrypts the database
                    encryptPasswordDatabase()

                # Deletes the record if it is found in the database
                else:
                    nameEntryField.delete(0, END)
                    cursor.execute("DELETE FROM pwManager where oid = " + deleteRecordID)
                    messagebox.showinfo("Information", "Deleted record %s!" %deleteRecordID)
                    launchPasswordGenerator.config(state="disabled")
                    deleteRecordEntryField.delete(0, END)
                    dbFrame.destroy()
                    
                    # Saves the changes in the database and closes the database connection
                    conn.commit()
                    conn.close()
                    # Encrypts the database
                    encryptPasswordDatabase()
                    
                    showRecords(4)

            # Displays an error if record ID does not exist in the database 
            except:
                messagebox.showerror("Error", "ID not found!")

        # Displays an error if no record ID is specified
        else:
            messagebox.showerror("Error", "ID must be specified!")

    # Function for hiding the password records  
    def hidePasswordRecords():
        dbFrame.destroy()
        mainWindow.minsize(360,220)
        mainWindow.maxsize(360,220)
        showRecordsButton.config(text="Show records", command= lambda: showRecords(3))

    # Function for updating the specified record
    def updatePasswordRecord():
        # Decrypts the database
        decryptPasswordDatabase()
        # Establishes a connection to the database and create a cursor
        conn = sqlite3.connect("pwManager.db")
        cursor = conn.cursor()

        # Updates the record if one of the four parameters have been filled (i.e. a changed value has been entered)
        if nameEntryField.get()!="" or urlEntryField.get()!="" or usernameEntryField.get()!="" or passwordEntryField.get()!="":
            checksum = 0
            if nameEntryField.get()!="":
                cursor.execute("""UPDATE pwManager SET
                            appName = :appName
                                
                            WHERE oid = :oid""",
                            {
                            'appName': nameEntryField.get(),
                            'oid': editRecordEntryField.get()
                            }
                )
                checksum += 1
                
            if usernameEntryField.get()!="":
                cursor.execute("""UPDATE pwManager SET
                            username = :username
                                
                            WHERE oid = :oid""",
                            {
                            'username': usernameEntryField.get(),
                            'oid': editRecordEntryField.get()
                            }
                )
                checksum += 1
                
            if urlEntryField.get()!="":
                cursor.execute("""UPDATE pwManager SET
                            url = :url
                                
                            WHERE oid = :oid""",
                            {
                            'url': urlEntryField.get(),
                            'oid': editRecordEntryField.get()
                            }
                )
                checksum += 1
                    
            if passwordEntryField.get()!="":
                cursor.execute("""UPDATE pwManager SET
                            password = :password
                                
                            WHERE oid = :oid""",
                            {
                            'password': passwordEntryField.get(),
                            'oid': editRecordEntryField.get()
                            }
                )
                checksum += 1
                
            # Saves the changes in the database and closes the database connection
            conn.commit()
            conn.close()
            # Encrypts the database
            encryptPasswordDatabase()
            
            # Displays information message and resets all buttons and other fields if a record has been updated
            if(checksum!=0):
                messagebox.showinfo("Information", "Record updated!")
                passwordEntryField.config(state=NORMAL)
                passwordEntryField.delete(0, END)
                urlEntryField.delete(0, END)
                usernameEntryField.delete(0, END)
                nameEntryField.delete(0, END)
                dbFrame.destroy()
                showRecords(3)
                addRecordButton.config(text="Add record", command=addRecordToDatabase)
                showRecordsButton.config(text="Hide records", command=hidePasswordRecords)
                deleteRecordEntryField.config(state=NORMAL)
                editRecordEntryField.config(state=NORMAL)
                editRecordEntryField.delete(0, END)
                editRecordEntryField.insert(END, "Please enter ID")
            
        # Displays an error if record ID does not exist in the database
        else:
            messagebox.showerror("Error", "ID not found")

    # Checks if the specified ID is valid and the record can be edited
    def preUpdateRecord():
        updateRecordID = editRecordEntryField.get()
        # Checks if an ID has been specified
        if(updateRecordID!=""):
            # Decrypts the database
            decryptPasswordDatabase()
            # Establishes a connection to the database and create a cursor
            conn = sqlite3.connect("pwManager.db")
            cursor = conn.cursor()

            # Checks if the specified ID exists in the database
            try:
                cursor.execute("Select appName from pwManager where oid = " +updateRecordID)
                checkIfRecordExists = cursor.fetchall()
                nameEntryField.delete(0, END)
                nameEntryField.insert(END, checkIfRecordExists)
                
                # Displays an error if record ID does not exist in the database
                if(nameEntryField.get()==""):
                    messagebox.showerror("Error", "ID not found!")
                    deleteRecordEntryField.config(state=NORMAL)
                    editRecordEntryField.config(state=NORMAL)

                # Outputs the saved values if the record exists in the database
                else:
                    addRecordButton.config(text="Update record", command=updatePasswordRecord)
                    showRecordsButton.config(text="Cancel", command=cancelUpdatingRecord)
                    deleteRecordEntryField.config(state=DISABLED)
                    editRecordEntryField.config(state=DISABLED)
                    
                    cursor.execute("Select url from pwManager where oid = " +updateRecordID)
                    record = cursor.fetchall()
                    urlEntryField.delete(0, END)
                    urlEntryField.insert(END, record)
                    
                    # Removes placeholder brackets if optional URL has not been set
                    urlTest = urlEntryField.get()
                    if(urlTest=="{{}}"):
                        urlEntryField.delete(0, END)
                    
                    cursor.execute("Select username from pwManager where oid = " +updateRecordID)
                    record = cursor.fetchall()
                    usernameEntryField.delete(0, END)
                    usernameEntryField.insert(END, record)
                    
                    cursor.execute("Select password from pwManager where oid = " +updateRecordID)
                    record = cursor.fetchall()
                    passwordEntryField.config(state=NORMAL)
                    passwordEntryField.delete(0, END)
                    passwordEntryField.insert(END, record)
                    passwordEntryField.config(show="*")
                    
                    # Removes brackets if they have been automatically added by mistake (e.g. # -> {{#}})
                    removeBracketsInPassword = passwordEntryField.get()
                    removeBracketsInName = nameEntryField.get()
                    if("{{" in removeBracketsInPassword):
                        passwordEntryField.delete(0, END)
                        removeBracketsInPassword = removeBracketsInPassword.replace("{{", "")
                        removeBracketsInPassword = removeBracketsInPassword.replace("}}", "")
                        passwordEntryField.insert(END, removeBracketsInPassword)
                    if("{{" in removeBracketsInName):
                        nameEntryField.delete(0, END)
                        removeBracketsInName = removeBracketsInName.replace("{{", "")
                        removeBracketsInName = removeBracketsInName.replace("}}", "")
                        nameEntryField.insert(END, removeBracketsInName)

            # Displays an error message if the ID does not exist in the database
            except:
                messagebox.showerror("Error", "ID not found!")
                
            # Saves the changes in the database and closes the database connection
            conn.commit()
            conn.close()
            # Encrypts the database
            encryptPasswordDatabase()
        
        else:
            messagebox.showerror("Error", "No ID specified!")

    # Function for cancelling the operation of updating a record if cancel button is clicked
    def cancelUpdatingRecord():
        addRecordButton.config(text="Add record", command=addRecordToDatabase)
        showRecordsButton.config(text="Hide records", command=hidePasswordRecords)
        deleteRecordEntryField.config(state=NORMAL)
        editRecordEntryField.config(state=NORMAL)
        # Deletes the outputted values
        editRecordEntryField.delete(0, END)
        nameEntryField.delete(0, END)
        urlEntryField.delete(0, END)
        usernameEntryField.delete(0, END)
        passwordEntryField.delete(0, END)

    # Function for creating the button for showing and hiding the records
    def createEyeButtons():
        global showHidePWsButton
        global photo
        photo = PhotoImage(file="images/icons/eye_crossed.png")
        showHidePWsButton = Button(mainWindow, image=photo, command=showFirstRecords, bg="blue")
        showHidePWsButton.grid(row=8, column=1, sticky="e", padx= (1,20))
        global newPhoto
        newPhoto = PhotoImage(file="images/icons/eye_opened.png")

    # Function for hiding records if button is clicked
    def hideRecords():
        dbFrame.destroy()
        showRecords(1)
        showHidePWsButton.config(image=photo, command=showFirstRecords)

    # Function for showing records if button is clicked
    def showFirstRecords():
        dbFrame.destroy()
        showRecords(2)
        showHidePWsButton.config(image=newPhoto, command=hideRecords)

    # Function for showing records if button is clicked
    def showRecords(x):
        # Creates a frame for the records
        global dbFrame
        try:
            dbFrame.destroy()
        except:
            pass
        dbFrame = Frame(mainWindow, highlightbackground="#3a3b3c", highlightthickness=4)
        dbFrame.place(relx=0.51, rely=0.5, relwidth=0.99, relheight=0.6, anchor = "n")
        
        # Creates a horizontal scrollbar
        horizontalScrollbar = Scrollbar(dbFrame, orient = 'horizontal')
        horizontalScrollbar.pack(side = BOTTOM, fill = X)
        
        # Creates a vertical scrollbar
        verticalScrollbar = Scrollbar(dbFrame, orient= 'vertical')
        verticalScrollbar.pack(side = RIGHT, fill = Y)
        
        # Creates a text window for holding all records
        global recordTextWindow
        recordTextWindow = Text(dbFrame, width = 67, height = 20, wrap = NONE, xscrollcommand = horizontalScrollbar.set,  
                    yscrollcommand = verticalScrollbar.set, fg=colorWhite, bg="#212121")
        recordTextWindow.pack()
        horizontalScrollbar.config(command=recordTextWindow.xview)
        verticalScrollbar.config(command=recordTextWindow.yview)
        
        # Decrypts the database
        decryptPasswordDatabase()
        # Establishes a connection to the database and create a cursor
        conn = sqlite3.connect("pwManager.db")
        cursor = conn.cursor()
        
        if(x==1):
            createEyeButtons()
            
            # Lists all records, but displays the password illegibly
            passwordEntryField.config(show="*")
            cursor.execute("SELECT *, oid FROM pwManager")
            records = cursor.fetchall()
            displayedRecords = ""
            for record in records:
                displayedRecords += "ID:" + "\t\t\t" + str(record[4])+ "\n" + "Name:" + "\t\t\t" + str(record[0])+ "\n" + "Username:" + "\t\t\t" + str(record[1])+ "\n" + "URL:" + "\t\t\t" + str(record[2]) + "\n" + "Password:" + "\t\t\t" + "**************"+ "\n--------------------------------------------------------------\n"

            recordTextWindow.insert(END, displayedRecords)
            recordTextWindow.config(state=DISABLED)
        elif (x==2):
            createEyeButtons()
            
            # Displays the passwords legibly
            passwordEntryField.config(show="*")
            cursor.execute("SELECT *, oid FROM pwManager")
            records = cursor.fetchall()
            displayedRecords = ""
            for record in records:
                displayedRecords += "ID:" + "\t\t\t" + str(record[4])+ "\n" + "Name:" + "\t\t\t" + str(record[0])+ "\n" + "Username:" + "\t\t\t" + str(record[1])+ "\n" + "URL:" + "\t\t\t" + str(record[2]) + "\n" + "Password:" + "\t\t\t" + str(record[3])+ "\n--------------------------------------------------------------\n"

            recordTextWindow.insert(END, displayedRecords)
            recordTextWindow.config(state=DISABLED)
        
        elif(x==3):
            # Sets the window size
            mainWindow.minsize(360, 600)
            mainWindow.maxsize(360, 600)
            
            # Creates the buttons and entry fields for deleting a record
            deleteRecordButton = Button(mainWindow, text="Delete record", command=deleteRecordFromDatabase, fg=colorBlack, bg=backgroundColor)
            deleteRecordButton.grid(row=7, column=0)
            global deleteRecordEntryField
            deleteRecordEntryField = Entry(mainWindow, fg=colorBlack, bg=entryBackgroundColor, insertbackground="black")
            deleteRecordEntryField.grid(row=7, column=1, sticky="w", padx=25)
            deleteRecordEntryField.insert(END, "Enter record ID")
            deleteRecordEntryField.config(font="Consolas 11 italic")
            # Creates the buttons and entry fields for updating a record
            updateRecordButton = Button(mainWindow, text="Edit record", command=preUpdateRecord, fg=colorBlack, bg=backgroundColor)
            updateRecordButton.grid(row=8, column=0)
            global editRecordEntryField
            editRecordEntryField = Entry(mainWindow, fg=colorBlack, bg=entryBackgroundColor, insertbackground="black")
            editRecordEntryField.grid(row=8, column=1, sticky="w", padx=25)
            editRecordEntryField.insert(END, "Enter record ID")
            editRecordEntryField.config(font="Consolas 11 italic")
            showRecordsButton.config(text="Hide records", command=hidePasswordRecords)
            
            # Function for removing the placeholder text in the entry field for deleting a record
            def removePlaceholderInDeleteEntry(event):
                deleteRecordEntryField.delete(0, END)
                deleteRecordEntryField.unbind('<Button-1>', removePlaceHolderInDeleteEntryBind)
            removePlaceHolderInDeleteEntryBind = deleteRecordEntryField.bind('<Button-1>', removePlaceholderInDeleteEntry)
            
            # Function for removing the placeholder text in the entry field for updating a record
            def removePlaceholderInUpdateEntry(event):
                editRecordEntryField.delete(0, END)
                editRecordEntryField.unbind('<Button-1>', removePlaceHolderInUpdateEntryBind)
            removePlaceHolderInUpdateEntryBind = editRecordEntryField.bind('<Button-1>', removePlaceholderInUpdateEntry)
            
            createEyeButtons()
            
            # Lists all database records
            cursor.execute("SELECT *, oid FROM pwManager")
            records = cursor.fetchall()
            displayedRecords = ""
            for record in records:
                displayedRecords += "ID:" + "\t\t\t" + str(record[4])+ "\n" + "Name:" + "\t\t\t" + str(record[0])+ "\n" + "Username:" + "\t\t\t" + str(record[1])+ "\n" + "URL:" + "\t\t\t" + str(record[2]) + "\n" + "Password:" "\t\t\t" + "**************" + "\n--------------------------------------------------------------\n"
            recordTextWindow.insert(END, displayedRecords)
            recordTextWindow.config(state=DISABLED)
            
        elif(x==4):
            # Lists all database records
            cursor.execute("SELECT *, oid FROM pwManager")
            records = cursor.fetchall()
            displayedRecords = ""
            for record in records:
                displayedRecords += "ID:" + "\t\t\t" + str(record[4])+ "\n" + "Name:" + "\t\t\t" + str(record[0])+ "\n" + "Username:" + "\t\t\t" + str(record[1])+ "\n" + "URL:" + "\t\t\t" + str(record[2]) + "\n" + "Password:" "\t\t\t" + "**************" + "\n--------------------------------------------------------------\n"
            recordTextWindow.insert(END, displayedRecords)
            recordTextWindow.config(state=DISABLED)
            
        # Saves the changes in the database and closes the database connection
        conn.commit()
        conn.close()
        # Encrypts the database
        encryptPasswordDatabase()

    # Sets global variables
    global nameEntryField, usernameEntryField, urlEntryField, passwordEntryField

    # Creates the entry fields for the password parameters
    nameEntryField = Entry(mainWindow, width=25, fg=colorBlack, bg=entryBackgroundColor, insertbackground="black")
    nameEntryField.grid(row=0, column=1, padx=25, pady=5)
    usernameEntryField = Entry(mainWindow, width=25, fg=colorBlack, bg=entryBackgroundColor, insertbackground="black")
    usernameEntryField.grid(row=1, column=1, padx=20, pady=5)
    urlEntryField = Entry(mainWindow, width=25, fg=colorBlack, bg=entryBackgroundColor, insertbackground="black")
    urlEntryField.grid(row=2, column=1, padx=20, pady=5)
    passwordEntryField = Entry(mainWindow, width=25, show="*", fg=colorBlack, bg=entryBackgroundColor, insertbackground="black")
    passwordEntryField.grid(row=4, column=1, padx=20, pady=5)

    # Creates the labels for the password parameters
    nameEingabeLabel = Label(mainWindow, text="Name:", fg=colorWhite, bg=backgroundColor)
    nameEingabeLabel.grid(row=0, column=0)
    userNameEntryLabel = Label(mainWindow, text="Username:", fg=colorWhite, bg=backgroundColor)
    userNameEntryLabel.grid(row=1, column=0)
    urlEntryLabel = Label(mainWindow, text="URL (optional):", fg=colorWhite, bg=backgroundColor)
    urlEntryLabel.grid(row=2, column=0)
    passwordEntryLabel = Label(mainWindow, text="Password:", fg=colorWhite, bg=backgroundColor)
    passwordEntryLabel.grid(row=4, column=0)

    # Creates the radiobuttons
    getRadiobuttonValue = StringVar()
    manualRadiobutton = Radiobutton(mainWindow, text="Manual password", variable=getRadiobuttonValue, value="M", command=checkPasswordManualGenerated, fg=colorWhite, bg=backgroundColor, selectcolor=buttonBackgroundColor)
    manualRadiobutton.grid(row=3, column=1, sticky="w", padx=18)
    automaticRadiobutton = Radiobutton(mainWindow, text="Generate", variable=getRadiobuttonValue, value="A", command=checkPasswordManualGenerated, fg=colorWhite, bg=backgroundColor, selectcolor=buttonBackgroundColor)
    automaticRadiobutton.grid(row=3, column=1, sticky="e", padx=25)
    
    # Selects the manual radionbutton as default
    manualRadiobutton.select()
    global manualRadiobuttonSelected
    manualRadiobuttonSelected = True

    # Creates the button to launch the password generator
    launchPasswordGenerator = Button(mainWindow, text="Generate password", command=passwordGeneratorWindow, state=DISABLED, fg=colorBlack, bg=colorWhite, disabledforeground=colorBlack)
    launchPasswordGenerator.grid(row=3, column=0)

    # Creates the button to add a record to the database
    addRecordButton = Button(mainWindow, text="Add record", command=addRecordToDatabase, fg=colorBlack, bg=backgroundColor)
    addRecordButton.grid(row=5, column=0, padx=10, pady=20)

    # Creates the button to list the records from the database
    showRecordsButton = Button(mainWindow, text="Show records", command= lambda: showRecords(3), fg=colorBlack, bg=backgroundColor)
    showRecordsButton.grid(row=5, column=1, pady=20)


loginWindow.mainloop()