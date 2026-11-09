"""Curated target list: Australian organisations that plausibly collect sensitive information
(health, genetic, financial hardship, etc.) via their websites. Roughly size-ordered within sector.
NOT a strict revenue ranking - no public source ranks 'organisations that collect sensitive information'."""
import csv, sys
S = {
 "Private health insurance": "bupa.com.au medibank.com.au hcf.com.au nib.com.au hbf.com.au ahm.com.au australianunity.com.au teachershealth.com.au defencehealth.com.au gmhba.com.au cbhs.com.au peoplecare.com.au westfund.com.au navyhealth.com.au latrobehealth.com.au healthpartners.com.au doctorshealthfund.com.au phoenixhealthfund.com.au rthealthfund.com.au uhf.com.au frank.com.au allianzcare.com.au",
 "Hospitals & health services": "ramsayhealth.com healthscope.com.au sjog.org.au svha.org.au epworth.org.au cabrini.com.au calvarycare.org.au mater.org.au mercyhealth.com.au sah.org.au genesiscare.com icon.team aspenmedical.com myhealth.com.au healthengine.com.au hotdoc.com.au i-med.com.au integraldiagnostics.com.au lumus.com.au",
 "Pathology & diagnostics": "sonichealthcare.com healius.com.au clinicallabs.com.au qml.com.au dorevitch.com.au snp.com.au dhm.com.au",
 "Pharmacy & retail health": "chemistwarehouse.com.au priceline.com.au terrywhitechemmart.com.au amcal.com.au guardianpharmacies.com.au pharmacy4less.com.au discountdrugstores.com.au soulpattinson.com.au sigmahealthcare.com.au woolworths.com.au coles.com.au wesfarmers.com.au specsavers.com.au opsm.com amplifon.com blackmores.com.au swisse.com.au healthylife.com.au jennycraig.com.au",
 "Telehealth": "instantscripts.com.au doctor2u.com.au coviu.com",
 "IVF / fertility": "monashivf.com genea.com.au ivfaustralia.com.au virtushealth.com qfg.com.au cityfertility.com.au sydneyivf.com melbourneivf.com.au",
 "Mental health & community health": "headspace.org.au beyondblue.org.au lifeline.org.au blackdoginstitute.org.au smilingmind.com.au kidshelpline.com.au au.reachout.com sane.org jeanhailes.org.au fpnsw.org.au mariestopes.org.au acon.org.au cancer.org.au heartfoundation.org.au diabetesaustralia.com.au dementia.org.au redcross.org.au salvos.org.au vinnies.org.au",
 "Dental": "pacificsmiles.com.au 1300smiles.com.au",
 "Aged care & disability": "estiahealth.com.au regis.com.au arcare.com.au opalhealthcare.com.au silverchain.org.au anglicare.org.au anglicaresydney.org.au baptistcare.org.au hammondcare.com.au uniting.org mecwacare.org.au mable.com.au bluecare.org.au",
 "Medical devices & consumer health": "resmed.com cochlear.com",
 "General & life insurance": "iag.com.au nrmainsurance.com.au aami.com.au cgu.com.au suncorp.com.au gio.com.au qbe.com allianz.com.au youi.com.au budgetdirect.com.au hollard.com.au realinsurance.com.au tal.com.au aia.com.au zurich.com.au mlcinsurance.com.au clearview.com.au amp.com.au insignia.com.au covermore.com.au racq.com.au racv.com.au rac.com.au nrma.com.au",
 "Superannuation": "australiansuper.com australianretirementtrust.com.au aware.com.au unisuper.com.au cbussuper.com.au hostplus.com.au hesta.com.au rest.com.au telstrasuper.com.au caresuper.com.au firstsuper.com.au legalsuper.com.au mercer.com.au cfs.com.au css.gov.au",
 "Banking & finance": "commbank.com.au westpac.com.au anz.com.au nab.com.au macquarie.com bendigobank.com.au boq.com.au ing.com.au bankwest.com.au stgeorge.com.au bankofmelbourne.com.au banksa.com.au hsbc.com.au ubank.com.au zip.co latitudefinancial.com.au humm-group.com pepper.com.au mebank.com.au greater.com.au teachersmutualbank.com.au afterpay.com",
 "Gambling": "sportsbet.com.au tab.com.au ladbrokes.com.au neds.com.au bet365.com.au pointsbet.com.au unibet.com.au betfair.com.au bluebet.com.au crownresorts.com.au star.com.au",
 "Telco & energy": "telstra.com.au optus.com.au tpg.com.au vodafone.com.au originenergy.com.au agl.com.au energyaustralia.com.au alintaenergy.com.au",
 "Education & childcare": "goodstart.org.au g8education.edu.au unimelb.edu.au sydney.edu.au unsw.edu.au monash.edu uq.edu.au anu.edu.au uts.edu.au rmit.edu.au qut.edu.au deakin.edu.au",
 "Legal & employment": "slatergordon.com.au mauriceblackburn.com.au shine.com.au seek.com.au",
 "Travel & community": "qantas.com virginaustralia.com jetstar.com rsvp.com.au eharmony.com.au",
}
rows, seen = [], set()
for sector, doms in S.items():
    for d in doms.split():
        if d in seen or d.endswith(".gov.au"): continue
        seen.add(d); rows.append((d, sector))
with open(sys.argv[1], "w", newline="") as f:
    w = csv.writer(f); w.writerow(["domain", "url", "sector", "city", "title"])
    for d, s in rows: w.writerow([d, f"https://{d}/", s, "", ""])
print(len(rows))
