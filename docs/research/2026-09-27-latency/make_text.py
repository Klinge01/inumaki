import random
random.seed(7)
first = ["Sarah","Jürgen","Anna","Thomas","Katharina","Lukas","Maria","Stefan","Elif","Mehmet","Julia","Florian"]
last = ["Leitner","Müller","Huber","Gruber","Wagner","Pichler","Steiner","Moser","Hofer","Bauer","Yilmaz","Novak"]
streets = ["Neubaugasse 22","Mariahilfer Straße 45","Linzer Straße 7","Hauptplatz 3","Schönbrunner Str. 118"]
cities = ["1070 Wien","4020 Linz","8010 Graz","5020 Salzburg","6020 Innsbruck"]
de = ["Sehr geehrte Frau {n}, vielen Dank für Ihre Nachricht vom 12. März bezüglich der offenen Rechnung RE-2024-{d}.",
      "Wie telefonisch mit {n} besprochen, senden wir Ihnen die korrigierte Abrechnung an {s}, {c}.",
      "Bitte überweisen Sie den Betrag auf das Konto AT61 1904 3002 3457 {d} bis Ende des Monats.",
      "Unser Techniker {n} wird am Donnerstag zwischen 8 und 12 Uhr bei Ihnen vorbeikommen.",
      "Meine Tochter hatte letzte Woche einen Unfall, deshalb konnte ich mich nicht früher melden.",
      "Die Kundennummer K-{d} ist im System hinterlegt; bei Rückfragen erreichen Sie uns unter +43 1 234 {d}.",
      "Mit freundlichen Grüßen\n{n}\nKundenservice, Energie Beispiel GmbH\n{s}, {c}\n"]
en = ["Hi {n}, following up on our call yesterday about the contract renewal for the office at {s}, {c}.",
      "Could you forward the signed documents to {n} in accounting before Friday?",
      "The invoice INV-{d} was sent to billing@example.com but bounced twice.",
      "We noticed the meter reading for customer K-{d} looks unusually high compared to last year.",
      "Best regards,\n{n}\nOperations Lead\n"]
out=[]
while sum(len(x.encode()) for x in out) < 5000:
    t = random.choice(de+en)
    out.append(t.format(n=random.choice(first)+" "+random.choice(last), s=random.choice(streets), c=random.choice(cities), d=random.randint(100000,999999)))
s=" ".join(out)
open("text5k.txt","w").write(s)
print(len(s.encode()), len(s.split()))
