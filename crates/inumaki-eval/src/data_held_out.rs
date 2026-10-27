//! Held-out family (spec §13.1): identities, places, organizations, and
//! templates disjoint from `data.rs`. Never tune thresholds, labels,
//! stoplists, or dictionaries against this file; the test
//! `held_out_lists_are_disjoint_from_tuning_lists` keeps the lists apart.

/// First names not in `data::FIRST_NAMES`.
pub const FIRST_NAMES: &[&str] = &[
    "Bernhard",
    "Claudia",
    "Dominik",
    "Eva",
    "Franz",
    "Gerlinde",
    "Helmut",
    "Isabella",
    "Jakob",
    "Karin",
    "Leonie",
    "Manfred",
    "Nadine",
    "Oskar",
    "Paula",
    "Raphael",
    "Sabine",
    "Theresa",
    "Ulrich",
    "Valentina",
    "Wolfgang",
    "Xenia",
    "Yasmin",
    "Zeynep",
    "Amir",
    "Bojan",
    "Elif",
    "Goran",
    "Hüseyin",
    "Ines",
    "Jasmin",
    "Konstantin",
    "Liesl",
    "Milan",
    "Noah",
];

/// Surnames not in `data::LAST_NAMES`.
pub const LAST_NAMES: &[&str] = &[
    "Auer",
    "Binder",
    "Czerny",
    "Dorner",
    "Ebner",
    "Fröhlich",
    "Gasser",
    "Hackl",
    "Illichmann",
    "Jandl",
    "Kern",
    "Lackner",
    "Mitterer",
    "Neumann",
    "Obermayr",
    "Pertl",
    "Rainer",
    "Schober",
    "Trummer",
    "Unterberger",
    "Vogl",
    "Wieser",
    "Zehetner",
    "Đorđević",
    "Ćosić",
    "Kaya",
    "Demir",
    "Petrović",
    "Nowak",
    "Achebe",
    "Lindqvist",
    "Sørensen",
    "Baptiste",
    "Farkas",
    "Molnár",
];

/// Streets not in `data::STREETS`; includes abbreviated and two-word forms.
pub const STREETS: &[&str] = &[
    "Rennweg",
    "Taborstraße",
    "Gumpendorfer Straße",
    "Währinger Straße",
    "Nußdorfer Straße",
    "Lerchenfelder Str.",
    "Kaiserstraße",
    "Zieglergasse",
    "Stiftgasse",
    "Mozartplatz",
    "Rosenweg",
    "Feldgasse",
    "Kirchenplatz",
    "Am Anger",
    "Schubertring",
    "Rathausplatz",
    "Salzburger Straße",
    "Innsbrucker Str.",
    "Wiener Neustädter Straße",
    "Auhofstraße",
    "Simmeringer Hauptstraße",
    "Obere Donaustraße",
    "Untere Augartenstraße",
    "Alte Poststraße",
    "Im Winkel",
];

/// Postal code and city pairs not in `data::CITIES`.
pub const CITIES: &[(&str, &str)] = &[
    ("9500", "Villach"),
    ("6850", "Dornbirn"),
    ("3500", "Krems an der Donau"),
    ("4400", "Steyr"),
    ("8700", "Leoben"),
    ("2500", "Baden"),
    ("2100", "Korneuburg"),
    ("5280", "Braunau am Inn"),
    ("93047", "Regensburg"),
    ("90402", "Nürnberg"),
    ("04109", "Leipzig"),
    ("28195", "Bremen"),
    ("6003", "Luzern"),
    ("8400", "Winterthur"),
    ("7000", "Chur"),
];

/// Invented organizations not in `data::ORGS`.
pub const ORGS: &[&str] = &[
    "Salzach Energie GmbH",
    "Mur Immobilien KG",
    "Ordination Dr. Rainer",
    "Tiroler Dachdecker OG",
    "Ennstal Transporte GmbH",
    "Nordsee Versicherungs AG",
    "Klinikum Weinviertel",
    "Steirische Wohnbau GmbH",
    "Bodensee Software AG",
    "Café Auer",
    "Fitnessstudio Aktiv Baden",
    "Volksschule Leoben-Stadt",
];

/// Mail domains not in `data::DOMAINS`.
pub const DOMAINS: &[&str] = &[
    "aon.at",
    "posteo.de",
    "hotmail.com",
    "yahoo.de",
    "bluewin.ch",
];

/// German greetings.
pub const DE_GREETINGS: &[&str] = &[
    "Sehr geehrtes Kundenservice-Team,",
    "Guten Morgen,",
    "Werte Damen und Herren,",
    "Hallo zusammen,",
];

/// English greetings.
pub const EN_GREETINGS: &[&str] = &[
    "Good morning,",
    "To whom it may concern,",
    "Hello team,",
    "Dear customer service,",
];

/// German closings.
pub const DE_CLOSINGS: &[&str] = &[
    "Herzliche Grüße\n{PERSON}",
    "Schöne Grüße aus {ZIP_CITY}\n{FIRST}",
    "Mit besten Grüßen\n{PERSON}\n{ADDRESS_BLOCK}",
    "Danke im Voraus,\n{FIRST} {LAST}",
];

/// English closings.
pub const EN_CLOSINGS: &[&str] = &[
    "Yours sincerely,\n{PERSON}",
    "Many thanks,\n{FIRST}",
    "All the best,\n{PERSON}\n{ADDRESS_BLOCK}",
    "Cheers,\n{FIRST} {LAST}",
];

/// German signature block with an address block.
pub const DE_SIGNATURE: &str = "\n\n--\n{PERSON}\n{ADDRESS_BLOCK}\nMobil {PHONE}\n{EMAIL}\n{ORG}";

/// English signature block with an address block.
pub const EN_SIGNATURE: &str = "\n\n--\n{PERSON}\n{ADDRESS_BLOCK}\nMobile {PHONE}\n{EMAIL}\n{ORG}";

/// German quoted reply with a second person and a subject line.
pub const DE_QUOTE: &str = "\n\n-----Ursprüngliche Nachricht-----\nVon: {PERSON2} <{EMAIL2}>\nGesendet: {DATE}\nBetreff: AW: Ihre Anfrage\n\nGuten Tag, wir haben Ihre Nachricht erhalten und melden uns.\n{ORG}";

/// English quoted reply with a second person and a subject line.
pub const EN_QUOTE: &str = "\n\n-----Original Message-----\nFrom: {PERSON2} <{EMAIL2}>\nSent: {DATE}\nSubject: Re: your request\n\nHello, we received your message and will get back to you.\n{ORG}";

/// German scenarios (insurance, housing, medical, HR, warranty, memberships, school, repair).
pub const DE_TEMPLATES: &[&str] = &[
    "Betreff: Schadensmeldung {CONTRACT_ID}\n\nam {DATE} wurde mein Fahrzeug {PLATE} auf dem Parkplatz beschädigt. Bitte melden Sie sich unter {PHONE}.",
    "Betreff: Wohnungsübergabe\n\ndie Übergabe der Wohnung {STREET} findet am {DATE} statt. Der neue Mieter ist {PERSON2}, erreichbar unter {EMAIL2}.",
    "ich bitte um einen Termin in der Ordination. Patientin: {PERSON}, geboren {DOB}, versichert unter {CUSTOMER_ID}.",
    "als neuer Mitarbeiter benötige ich einen Zugang. Meine Daten: {PERSON}, {ADDRESS_BLOCK}, Telefon {PHONE}.",
    "das Gerät aus Rechnung {INVOICE_ID} ist defekt. Bitte holen Sie es bei {STREET}, {ZIP_CITY} ab.",
    "ich möchte meine Mitgliedschaft {CONTRACT_ID} pausieren. Bitte buchen Sie ab {DATE} nichts mehr von {IBAN} ab.",
    "zur Anmeldung meiner Tochter: {PERSON2}, geboren am {DOB}, wohnhaft {STREET}, {ZIP_CITY}.",
    "der Kostenvoranschlag {INVOICE_ID} für das Auto {PLATE} ist zu hoch. Rufen Sie mich bitte unter {PHONE} an.",
    "Betreff: Adressänderung\n\nbitte ändern Sie meine Rechnungsadresse auf:\n{ADDRESS_BLOCK}\nKundennummer {CUSTOMER_ID}.",
    "wir sind von der {ORG} und benötigen für Herrn {LAST} eine Kopie des Vertrags {CONTRACT_ID}.",
    "die Kartenzahlung mit {CARD} wurde doppelt gebucht. Bitte erstatten Sie den zweiten Betrag.",
    "mein Vater {PERSON2} kann nicht mehr selbst schreiben; bitte senden Sie künftig alles an {EMAIL}.",
    "Betreff: Rückruf\n\nich bin bis {DATE} nur unter {PHONE} erreichbar. Vertrag {CONTRACT_ID}, Adresse {STREET}.",
    "die Lieferung ging an die falsche Adresse. Richtig ist {STREET}, {ZIP_CITY}, nicht die alte Wohnung.",
    "bitte senden Sie die Unterlagen zur Versicherungsnummer {CUSTOMER_ID} an {PERSON}, {ADDRESS_BLOCK}.",
];

/// English scenarios.
pub const EN_TEMPLATES: &[&str] = &[
    "Subject: Claim {CONTRACT_ID}\n\non {DATE} my car {PLATE} was damaged in the car park. Please contact me on {PHONE}.",
    "Subject: Flat handover\n\nthe handover of the flat at {STREET} takes place on {DATE}. The new tenant is {PERSON2}, reachable at {EMAIL2}.",
    "I would like an appointment at the practice. Patient: {PERSON}, born {DOB}, insured under {CUSTOMER_ID}.",
    "as a new employee I need an account. My details: {PERSON}, {ADDRESS_BLOCK}, phone {PHONE}.",
    "the device from invoice {INVOICE_ID} is faulty. Please collect it from {STREET}, {ZIP_CITY}.",
    "I want to pause my membership {CONTRACT_ID}. Please stop debiting {IBAN} from {DATE}.",
    "to register my daughter: {PERSON2}, born on {DOB}, living at {STREET}, {ZIP_CITY}.",
    "the estimate {INVOICE_ID} for the car {PLATE} is too high. Please call me on {PHONE}.",
    "Subject: Change of address\n\nplease change my billing address to:\n{ADDRESS_BLOCK}\nCustomer number {CUSTOMER_ID}.",
    "we are from {ORG} and need a copy of contract {CONTRACT_ID} for Mr {LAST}.",
    "the card payment with {CARD} was booked twice. Please refund the second amount.",
    "my father {PERSON2} can no longer write himself; please send everything to {EMAIL} from now on.",
    "Subject: Call back\n\nuntil {DATE} I can only be reached on {PHONE}. Contract {CONTRACT_ID}, address {STREET}.",
    "the delivery went to the wrong address. The correct one is {STREET}, {ZIP_CITY}, not the old flat.",
    "please send the documents for policy number {CUSTOMER_ID} to {PERSON}, {ADDRESS_BLOCK}.",
];
