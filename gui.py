from tkinter import *
from tkinter import messagebox
import trainer as tr
import pandas
import main
from PIL import ImageTk, Image
import os

root = Tk()
root.geometry('1100x600+500+800')
root.configure(background = "#001a4d")
frame = Frame(root)
frame.pack()
bottomframe = Frame(root)
bottomframe.pack(side = BOTTOM)


im = Image.open('image.png').resize((1100,500))#width,height
#size= width,height = im.size
#im.resize((5000,128))
img = ImageTk.PhotoImage(im)
panel = Label(root, image = img)
#panel.pack(side = "bottom", fill = "both", expand = "yes")
panel.pack()

L1 = Label(frame, text="Enter the URL: ",fg="MidnightBlue",font = 'times 17 bold underline')# for text enter the url
L1.pack( side = LEFT)
E1 = Entry(frame,bd =35, width=180,fg="#001a4d" ,bg="AliceBlue")# for text box
#E1.insert(0, 'Enter your URL')
E1.pack(side = RIGHT)

def submitCallBack():
	url=E1.get()
	main.process_test_url(url,'gui_url_features.csv')
	return_ans = tr.gui_caller('train_features.csv','gui_url_features.csv')
	a=str(return_ans).split()
	if int(a[1])== -1:
		messagebox.showinfo( "URL Checker Result","The URL "+url+" is VALID URL")
	elif int(a[1])==1:
		messagebox.showinfo( "URL Checker Result","The URL "+url+" is PHISHING URL")
	else:
		messagebox.showinfo( "URL Checker Result","The URL "+url+" is MALWARE")
   		   
B1 = Button(bottomframe, text ="Submit", command = submitCallBack,bg="LightSeaGreen",height=3,width=10)

B1.pack()

root.mainloop()

