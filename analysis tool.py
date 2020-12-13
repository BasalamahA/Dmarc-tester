import os 
import re
import xlsxwriter


# TODO: make the selector automatic after gather some list...  
# for later ... to make it auto...
#  list of dkim selectors 
#  dkim, google, selector1, s2048g, 

# geting Spf1 .... 
Domain = input("Enter the domain >>>  ")
DKIM_Selector = input("Enter DKIM Selector >>>  ")

DMARC_output = os.system('dig _dmarc.' + Domain + ' txt | findstr "v=DMARC1" > Needed_DATA.txt')
spf_output = os.system('dig ' + Domain + ' txt | findstr "v=spf1" >> Needed_DATA.txt')
if DKIM_Selector != '':
    dkim_output = os.system('dig txt ' + DKIM_Selector + '._domainkey.' + Domain + ' | findstr "v=DKIM1" >> Needed_DATA.txt')
# ================================================================

result = open("Needed_DATA.txt" , 'r')
readed = result.readlines()
result.close

# print (readed)
# add beaty filter ......... 
DMARC_Value = readed[0]
spf_Value = readed[1]
if DKIM_Selector != '':
    DKIM_Selector = readed[2]
# -----------------------
# print (DMARC_Value) --- DONE! 
# print (spf_Value) ----- DONE! 
# print (DKIM_Selector) - DONE!

# =============================================================
#      DMARC part !
# =============================================================

def get_dmarc(DMARC_Value):
    try:
        tag_include__regx = r"v=DMARC1[A-Za-z=;\s0-9:@.,]+"
        tag_dmarc = re.search(tag_include__regx, DMARC_Value)
        print("========  DMARC  ==================================\n")
        print (tag_dmarc.group())
        print("\n")
        return tag_dmarc
    except Exception:
        return ("N/A")

# =============================================================
#      SPF part !
# =============================================================

def get_spf(spf_Value):
    try:
        tag_include__regx = r"v=spf1[\sA-Za-z0-9-:./\?\+~_]+"
        tag_spf = re.search(tag_include__regx, spf_Value)
        print("=========  SPF  ===================================\n")
        print (tag_spf.group())
        print("\n")
        return tag_spf
    except Exception:
        return ("N/A")

# =============================================================
#      dkim part ! if any ...... 
# =============================================================

def get_DKIM(DKIM_Selector):
    try:
        tag_include__regx = r"v=DKIM1[A-Za-z0-9;\s=\/+]+"
        tag_DKIM = re.search(tag_include__regx, DKIM_Selector)
        print("========  DKIM  ===================================\n")
        print (tag_DKIM.group())
        print("\n")
        return tag_DKIM
    except Exception:
        return ("N/A")

# =============================================================
if __name__ == "__main__":
    get_dmarc(DMARC_Value)
    get_spf(spf_Value)
    if DKIM_Selector != '':
        get_DKIM(DKIM_Selector)