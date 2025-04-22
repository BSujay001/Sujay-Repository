#set page(width: 210mm, height: 297mm, margin: 20mm)

#align(center)[#underline[*OPD*]]

#v(7pt)

#grid(
  columns: (1fr, 1fr, 1fr),
  gutter: 5pt,
  [*Patient Name:* #patientname],
  [*Doctor Name:* #drname],
  [*OPD Date:* #createdon]
)
#line(length: 100%) 

#grid(
  columns: (1fr),
  gutter: 10pt,
  [*OPD Notes:* #opdnotes ],
 
  [*Prescription:*   #prescription],

  [*Follow-up Date:*#followupdate ], 
  
) 

#v(5pt)

#line(length: 100%) 

#strong[Created on:] #createdon

#align(center)[-- END OF REPORT --]
