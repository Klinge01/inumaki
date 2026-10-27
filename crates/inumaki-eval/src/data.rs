//! Name, place, and organization lists for the generator. Fictional
//! combinations; the organizations are invented.

/// First names common in Austria and Germany plus international ones,
/// including names that are ordinary words.
pub const FIRST_NAMES: &[&str] = &[
    "Sarah",
    "Thomas",
    "Katharina",
    "Lukas",
    "Anna",
    "Markus",
    "Elisabeth",
    "Maximilian",
    "Julia",
    "Stefan",
    "Johanna",
    "Florian",
    "Lena",
    "Michael",
    "Sophie",
    "David",
    "Magdalena",
    "Andreas",
    "Laura",
    "Christoph",
    "Hannah",
    "Matthias",
    "Lea",
    "Tobias",
    "Marie",
    "Jürgen",
    "Birgit",
    "Günther",
    "Ingrid",
    "Jörg",
    "May",
    "Rose",
    "Hunter",
    "Grace",
    "Victor",
    "Ümit",
    "Ayşe",
    "Mehmet",
    "Dragana",
    "Nikola",
    "Agnieszka",
    "Piotr",
    "Ngozi",
    "Wei",
    "Priya",
    "Olga",
    "Ivan",
    "Fatima",
    "Carlos",
    "Emma",
];

/// Surnames, including ones that are ordinary words.
pub const LAST_NAMES: &[&str] = &[
    "Leitner",
    "Gruber",
    "Huber",
    "Wagner",
    "Müller",
    "Pichler",
    "Moser",
    "Steiner",
    "Mayer",
    "Hofer",
    "Bauer",
    "Berger",
    "Fuchs",
    "Eder",
    "Fischer",
    "Schmid",
    "Winkler",
    "Weber",
    "Schwarz",
    "Maier",
    "Schneider",
    "Reiter",
    "Mayr",
    "Brunner",
    "Novak",
    "Horvat",
    "Kovač",
    "Yilmaz",
    "Öztürk",
    "Weiß",
    "König",
    "Kaiser",
    "Berg",
    "Hunter",
    "May",
    "Rose",
    "Wolf",
    "Lang",
    "Klein",
    "Groß",
    "Hofmann",
    "Schuster",
    "Lehner",
    "Aigner",
    "Wimmer",
    "Egger",
    "Haas",
    "Holzer",
    "Okonkwo",
    "Nguyen",
];

/// Street names in Austria and Germany.
pub const STREETS: &[&str] = &[
    "Neubaugasse",
    "Mariahilfer Straße",
    "Hauptstraße",
    "Landstraßer Hauptstraße",
    "Kärntner Straße",
    "Wiedner Hauptstraße",
    "Favoritenstraße",
    "Praterstraße",
    "Linzer Straße",
    "Herrengasse",
    "Schönbrunner Straße",
    "Alser Straße",
    "Josefstädter Straße",
    "Thaliastraße",
    "Ottakringer Straße",
    "Grazer Straße",
    "Bahnhofstraße",
    "Kirchengasse",
    "Schulgasse",
    "Lindengasse",
    "Burggasse",
    "Goethestraße",
    "Schillerstraße",
    "Friedrichstraße",
    "Lange Gasse",
    "Am Graben",
    "Ringstraße",
    "Sonnenweg",
    "Waldweg",
    "Dorfstraße",
];

/// Postal code and city pairs in Austria, Germany and Switzerland.
pub const CITIES: &[(&str, &str)] = &[
    ("1010", "Wien"),
    ("1070", "Wien"),
    ("1100", "Wien"),
    ("8010", "Graz"),
    ("4020", "Linz"),
    ("5020", "Salzburg"),
    ("6020", "Innsbruck"),
    ("9020", "Klagenfurt"),
    ("3100", "St. Pölten"),
    ("2340", "Mödling"),
    ("3240", "Mank"),
    ("7000", "Eisenstadt"),
    ("6900", "Bregenz"),
    ("4600", "Wels"),
    ("2700", "Wiener Neustadt"),
    ("10115", "Berlin"),
    ("80331", "München"),
    ("20095", "Hamburg"),
    ("50667", "Köln"),
    ("60311", "Frankfurt"),
    ("70173", "Stuttgart"),
    ("01067", "Dresden"),
    ("8001", "Zürich"),
    ("3011", "Bern"),
    ("4051", "Basel"),
];

/// Invented organizations.
pub const ORGS: &[&str] = &[
    "Muster GmbH",
    "Leitner & Partner GmbH",
    "Alpenstrom AG",
    "Donau Logistik GmbH",
    "Huber Bau GmbH",
    "Stadtwerke Linz",
    "Wiener Wohnen Service GmbH",
    "Example GmbH",
    "Kärntner Versicherung AG",
    "Bergbahnen Tirol GmbH",
    "Schmid & Söhne OG",
    "Grüne Energie eG",
    "Nordlicht Software GmbH",
    "Café Central Betriebs GmbH",
    "Praxis Dr. Hofer",
];

/// Mail domains.
pub const DOMAINS: &[&str] = &[
    "gmx.at",
    "gmail.com",
    "a1.net",
    "outlook.com",
    "web.de",
    "chello.at",
    "icloud.com",
    "example.at",
];

/// Plate district prefixes.
pub const PLATE_PREFIXES: &[&str] = &["W", "G", "L", "S", "K", "I"];

/// German greetings.
pub const DE_GREETINGS: &[&str] = &[
    "Sehr geehrte Damen und Herren,",
    "Hallo,",
    "Guten Tag,",
    "Liebes Support-Team,",
];

/// English greetings.
pub const EN_GREETINGS: &[&str] = &[
    "Dear Sir or Madam,",
    "Hello,",
    "Hi there,",
    "Dear support team,",
];

/// German closings.
pub const DE_CLOSINGS: &[&str] = &[
    "Mit freundlichen Grüßen\n{PERSON}",
    "Viele Grüße\n{FIRST}",
    "LG {FIRST}",
    "Danke und beste Grüße,\n{PERSON}",
];

/// English closings.
pub const EN_CLOSINGS: &[&str] = &[
    "Kind regards,\n{PERSON}",
    "Best,\n{FIRST}",
    "Thanks,\n{FIRST}",
    "Regards\n{PERSON}",
];

/// German signature block.
pub const DE_SIGNATURE: &str = "\n\n--\n{PERSON}\n{ORG}\nTel. {PHONE}\n{EMAIL}";

/// English signature block.
pub const EN_SIGNATURE: &str = "\n\n--\n{PERSON}\n{ORG}\nPhone: {PHONE}\n{EMAIL}";

/// German quoted reply with a second person.
pub const DE_QUOTE: &str = "\n\n> Am {DATE} schrieb {PERSON2} <{EMAIL2}>:\n> Vielen Dank für Ihre Nachricht, wir kümmern uns darum.\n> Ihr Support-Team";

/// English quoted reply with a second person.
pub const EN_QUOTE: &str = "\n\n> On {DATE}, {PERSON2} <{EMAIL2}> wrote:\n> Thank you for your message, we are looking into it.\n> Your support team";

/// German scenarios.
pub const DE_TEMPLATES: &[&str] = &[
    "ich bin umgezogen und wohne jetzt in der {STREET}, {ZIP_CITY}. Meine Kundennummer ist {CUSTOMER_ID}. Bitte aktualisieren Sie meine Adresse.",
    "auf der Rechnung {INVOICE_ID} vom {DATE} wurde mir zu viel verrechnet. Bitte überweisen Sie die Differenz auf mein Konto {IBAN}.",
    "hiermit kündige ich meinen Vertrag {CONTRACT_ID} zum nächstmöglichen Termin. Sie erreichen mich unter {PHONE}.",
    "bitte rufen Sie mich unter {PHONE} zurück, es geht um die Lieferung an {STREET}, {ZIP_CITY}.",
    "Ihr Techniker war am {DATE} bei mir, aber das Problem besteht weiterhin. Mein Name ist {PERSON}, Kundennummer {CUSTOMER_ID}.",
    "ich möchte künftig per Lastschrift zahlen. Meine IBAN lautet {IBAN}, Kontoinhaber ist {PERSON}.",
    "leider muss ich den Termin am {DATE} verschieben. Könnten Sie mir einen neuen Termin an {EMAIL} schicken?",
    "für die Verifizierung: geboren am {DOB}, wohnhaft {STREET}, {ZIP_CITY}.",
    "wir sind Kunde der {ORG} und benötigen eine Kopie der Rechnung {INVOICE_ID}. Ansprechpartnerin ist Frau {LAST}.",
    "die Zahlung mit meiner Karte {CARD} ist fehlgeschlagen. Können Sie das prüfen?",
    "es geht um das Fahrzeug mit dem Kennzeichen {PLATE}, zugelassen auf {PERSON}.",
    "meine Mitbewohnerin {PERSON2} hat die Wohnung in der {STREET} übernommen, bitte schreiben Sie den Vertrag {CONTRACT_ID} auf sie um.",
    "Frau {LAST} hat mich gebeten, Ihnen das weiterzuleiten. Sie ist unter {EMAIL} erreichbar.",
    "anbei mein Zählerstand vom {DATE}. Kundennummer {CUSTOMER_ID}, Adresse {STREET}, {ZIP_CITY}.",
    "ich bitte um Auskunft über meine gespeicherten Daten. Name: {PERSON}, E-Mail: {EMAIL}, Telefon: {PHONE}.",
    "ich habe eine Mahnung zur Rechnung {INVOICE_ID} erhalten, obwohl ich am {DATE} von {IBAN} überwiesen habe.",
    "meine Tochter hatte letzte Woche einen Unfall, deshalb konnte ich den Termin nicht wahrnehmen. Bitte melden Sie sich unter {PHONE}.",
    "mein Nachbar {PERSON2} aus der {STREET} bekommt ständig meine Post. Können Sie das klären?",
    "ich möchte einen neuen Vertrag abschließen. Bitte senden Sie die Unterlagen an {PERSON}, {STREET}, {ZIP_CITY}.",
    "bitte erstatten Sie den Betrag auf die Karte {CARD} zurück. Bestellung vom {DATE}, Kundennummer {CUSTOMER_ID}.",
];

/// English scenarios.
pub const EN_TEMPLATES: &[&str] = &[
    "I have moved and now live at {STREET}, {ZIP_CITY}. My customer number is {CUSTOMER_ID}. Please update my address.",
    "invoice {INVOICE_ID} dated {DATE} charged me too much. Please refund the difference to my account {IBAN}.",
    "I would like to cancel my contract {CONTRACT_ID}. You can reach me at {PHONE}.",
    "please call me back on {PHONE} regarding the delivery to {STREET}, {ZIP_CITY}.",
    "your technician visited me on {DATE} but the problem persists. My name is {PERSON}, customer number {CUSTOMER_ID}.",
    "I want to pay by direct debit from now on. My IBAN is {IBAN}, account holder {PERSON}.",
    "I need to reschedule the appointment on {DATE}. Could you send a new date to {EMAIL}?",
    "for verification: date of birth {DOB}, address {STREET}, {ZIP_CITY}.",
    "we are a customer of {ORG} and need a copy of invoice {INVOICE_ID}. Our contact is Ms {LAST}.",
    "the payment with my card {CARD} failed. Can you check?",
    "this concerns the vehicle with plate {PLATE}, registered to {PERSON}.",
    "my flatmate {PERSON2} has taken over the flat at {STREET}; please transfer contract {CONTRACT_ID} to her.",
    "Mr {LAST} asked me to forward this to you. He can be reached at {EMAIL}.",
    "attached is my meter reading from {DATE}. Customer number {CUSTOMER_ID}, address {STREET}, {ZIP_CITY}.",
    "please send me all data you store about me. Name: {PERSON}, email: {EMAIL}, phone: {PHONE}.",
    "I received a reminder for invoice {INVOICE_ID} although I paid on {DATE} from {IBAN}.",
    "my daughter had an accident last week, so I missed the appointment. Please contact me at {PHONE}.",
    "my neighbour {PERSON2} from {STREET} keeps receiving my mail. Can you sort this out?",
    "I would like to sign a new contract. Please send the documents to {PERSON}, {STREET}, {ZIP_CITY}.",
    "please refund the amount to card {CARD}. Order from {DATE}, customer number {CUSTOMER_ID}.",
];
