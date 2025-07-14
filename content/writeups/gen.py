import sys
import os
if len(sys.argv) != 3 : 
    print("Generate template by python3 gen.py  $WU_NAME $Chal_NAME")
    exit()

wuName = sys.argv[1].lower()
challName = sys.argv[2].lower()
os.makedirs(wuName, exist_ok=True)
filename = wuName + ".md"

templateIntro =f'''+++
title = '{wuName}'
author = "3HLD"
description = "MaltaCTF is an international cybersecurity event organized by Friendly Maltese Citizens. The CTF features online preliminary rounds throughout 2025, with finals taking place alongside the MaltaCTF Conference held on-site in Valletta, Malta."
date = 2025-06-23T18:30:32+02:00
tags = [
    "CTF",
    "Web",
    "Crypto",
    "Pwn",
    "Reverse Engineering",
    "Misc",
]
type = 'list'
+++

#  {wuName}

## Performance Summary

- **CTFs**: 8/22
- **Total points**: 1966
- **Position**: 9/270
- **Rating points**: ?

## Writeups

#### Category

- [{challName}](/writeups/{wuName}/{challName}/)
'''

wuTemplate =  f'''+++
title = 'FANCY TEXT'
date = 2025-06-23T18:30:32+02:00
tags = [
  "web",
  "204 points",
  "25 solves",
  "downgrade"
]
draft = true
+++

YOUR MARDOWN GOES HERE
'''
if not os.path.exists(filename): 
    with open(filename , "w")  as f : 
        f.write(templateIntro)
else   : 
    with open(filename , "a")  as f : 
        f.write(f"\n- [{challName.capitalize()}](/writeups/{wuName}/{challName}/)")
    
with open(f'{wuName}/{challName}.md',"w") as f  :
    f.write(wuTemplate)

print("")
