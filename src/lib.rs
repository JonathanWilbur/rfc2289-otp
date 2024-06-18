//! # RFC 2289 One-Time Password
//! 
//! Implements the One-Time Password (OTP) algorithm described in
//! [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html), including
//! functions for parsing strings and mapping between dictionary words and OTP
//! values.
//! 
//! This algorithm is **NOT** the same as the TOTP and HOTP algorithms widely in use
//! today for multifactor authentication: these are defined in other RFCs. This
//! algorithm, however, is used in the `OTP` SASL mechanism as described in
//! [IETF RFC 2444](https://www.rfc-editor.org/rfc/rfc2444.html).
//! 
//! ## Security
//!
//! Note that there are only three hash algorithms defined for use with this
//! algorithm, **all of which are no longer considered secure**. These are:
//!
//! - MD4
//! - MD5
//! - SHA1
//!
//! **However**, I am of the non-professional opinion that these algorithms are
//! generally fine for the way that they are used by the OTP algorithm, because the
//! OTP algorithm performs the hash a fixed number of times with a fixed seed and a
//! passphrase. Still, I **highly** recommend using the `sha1` algorithm
//! exclusively. It is the newest and most secure of the three.
//!
//! If more algorithms are ever made official, you should see the new algorithms
//! [here](https://www.iana.org/assignments/otp-parameters/otp-parameters.xhtml).
//!
//! ## Feature Flags
//!
//! The feature flags for this library are:
//!
//! - `md4`: MD4 support
//! - `md5`: MD5 support
//! - `sha1`: SHA1 support
//! - `words`: Translation to and from dictionary words
//! - `dyndig`: Support for any digest that implements `digest::DynDigest`
//! - `parsing`: Parsing OTP strings
//!
//! All of the above are enabled by default.
//!
//! ## Usage
//!
//! Let's say you receive an OTP challenge as a string like so:
//!
//! ```text
//! otp-md5 499 ke1234 ext
//! ```
//!
//! Decode this string like so:
//!
//! ```rust
//! let challenge_str = "otp-md5 487 dog2";
//! let challenge = rfc2289_otp::parse_otp_challenge(challenge_str).unwrap();
//! ```
//!
//! If it is a valid string, you should get a data structure that looks like this:
//!
//! ```rust
//! pub struct OTPChallenge <'a> {
//!     pub hash_alg: &'a str,
//!     pub hash_count: usize,
//!     pub seed: &'a str,
//! }
//! ```
//!
//! You can use this data structure to calculate the OTP like so:
//!
//! ```rust
//! let challenge = rfc2289_otp::OTPChallenge {
//!     hash_alg: "md5",
//!     hash_count: 200,
//!     seed: "wibby123",
//! };
//! let extremely_secure_passphrase = "banana";
//! let otp = rfc2289_otp::calculate_otp(
//!     challenge.hash_alg,
//!     extremely_secure_passphrase,
//!     challenge.seed,
//!     challenge.hash_count,
//!     None,
//! ).unwrap();
//! ```
//!
//! If the algorithm was understood, and there wasn't any other problem, you should
//! get a `[u8; 8]` back (64-bits), which is your OTP value.
//!
//! You can directly convert this value to hex, and prepend `hex:` to it to produce
//! a valid OTP response.
//!
//! Or, you can convert it to dictionary words using the standard dictionary defined
//! in the specification using `convert_to_word_format`. Join these words with
//! spaces and prefix it with `word:`.
//!
//! If implementing an OTP server, you can parse these responses like so:
//!
//! ```rust
//! let otp_response = "hex:5Bf0 75d9 959d 036f";
//! let r = rfc2289_otp::parse_otp_response(&otp_response).unwrap();
//! ```
//!
//! If the syntax is valid, you should get an `OTPResponse` as shown below:
//!
//! ```rust
//! type Hex64Bit = [u8; 8];
//! 
//! pub enum HexOrWords <'a> {
//!     Hex(Hex64Bit),
//!     Words(&'a str),
//! }
//!
//! pub struct OTPInit <'a> {
//!     pub current_otp: HexOrWords<'a>,
//!     pub new_otp: HexOrWords<'a>,
//!     pub new_alg: &'a str,
//!     pub new_seq_num: usize,
//!     pub new_seed: &'a str,
//! }
//!
//! pub enum OTPResponse <'a> {
//!     Init(OTPInit <'a>),
//!     Current(HexOrWords<'a>)
//! }
//! ```
//!
//! The server will need to calculate the OTP and compare that value to the decoded
//! hex or words supplied by the client. You can decode words to the binary OTP
//! value using `decode_word_format_with_std_dict` like so:
//!
//! ```rust
//! let words = [ "AURA", "ALOE", "HURL", "WING", "BERG", "WAIT" ];
//! let decoded = rfc2289_otp::decode_word_format_with_std_dict(words).unwrap();
//! ```
//!
//! If the client response is one of the `Init` variants, how the server chooses to
//! handle this is an implementation detail.

#![no_std]
use cow_utils::CowUtils;
use md4::{Md4, Digest};
use hex::FromHex;

extern crate alloc;
use alloc::{borrow::ToOwned, boxed::Box};

/// Defined in [IETF RFC 1760](https://www.rfc-editor.org/rfc/rfc1760) for use
/// in S/KEY, but used OTP in
/// [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
/// 
/// This is a hard-coded dictionary that maps each word to 11-bits.
/// 
/// Used in [convert_to_word_format] and [decode_word_format_with_std_dict].
#[cfg(feature = "words")]
pub const STANDARD_DICTIONARY: [&'static str; 2048] = [
    "A",     "ABE",   "ACE",   "ACT",   "AD",    "ADA",   "ADD",
    "AGO",   "AID",   "AIM",   "AIR",   "ALL",   "ALP",   "AM",    "AMY",
    "AN",    "ANA",   "AND",   "ANN",   "ANT",   "ANY",   "APE",   "APS",
    "APT",   "ARC",   "ARE",   "ARK",   "ARM",   "ART",   "AS",    "ASH",
    "ASK",   "AT",    "ATE",   "AUG",   "AUK",   "AVE",   "AWE",   "AWK",
    "AWL",   "AWN",   "AX",    "AYE",   "BAD",   "BAG",   "BAH",   "BAM",
    "BAN",   "BAR",   "BAT",   "BAY",   "BE",    "BED",   "BEE",   "BEG",
    "BEN",   "BET",   "BEY",   "BIB",   "BID",   "BIG",   "BIN",   "BIT",
    "BOB",   "BOG",   "BON",   "BOO",   "BOP",   "BOW",   "BOY",   "BUB",
    "BUD",   "BUG",   "BUM",   "BUN",   "BUS",   "BUT",   "BUY",   "BY",
    "BYE",   "CAB",   "CAL",   "CAM",   "CAN",   "CAP",   "CAR",   "CAT",
    "CAW",   "COD",   "COG",   "COL",   "CON",   "COO",   "COP",   "COT",
    "COW",   "COY",   "CRY",   "CUB",   "CUE",   "CUP",   "CUR",   "CUT",
    "DAB",   "DAD",   "DAM",   "DAN",   "DAR",   "DAY",   "DEE",   "DEL",
    "DEN",   "DES",   "DEW",   "DID",   "DIE",   "DIG",   "DIN",   "DIP",
    "DO",    "DOE",   "DOG",   "DON",   "DOT",   "DOW",   "DRY",   "DUB",
    "DUD",   "DUE",   "DUG",   "DUN",   "EAR",   "EAT",   "ED",    "EEL",
    "EGG",   "EGO",   "ELI",   "ELK",   "ELM",   "ELY",   "EM",    "END",
    "EST",   "ETC",   "EVA",   "EVE",   "EWE",   "EYE",   "FAD",   "FAN",
    "FAR",   "FAT",   "FAY",   "FED",   "FEE",   "FEW",   "FIB",   "FIG",
    "FIN",   "FIR",   "FIT",   "FLO",   "FLY",   "FOE",   "FOG",   "FOR",
    "FRY",   "FUM",   "FUN",   "FUR",   "GAB",   "GAD",   "GAG",   "GAL",
    "GAM",   "GAP",   "GAS",   "GAY",   "GEE",   "GEL",   "GEM",   "GET",
    "GIG",   "GIL",   "GIN",   "GO",    "GOT",   "GUM",   "GUN",   "GUS",
    "GUT",   "GUY",   "GYM",   "GYP",   "HA",    "HAD",   "HAL",   "HAM",
    "HAN",   "HAP",   "HAS",   "HAT",   "HAW",   "HAY",   "HE",    "HEM",
    "HEN",   "HER",   "HEW",   "HEY",   "HI",    "HID",   "HIM",   "HIP",
    "HIS",   "HIT",   "HO",    "HOB",   "HOC",   "HOE",   "HOG",   "HOP",
    "HOT",   "HOW",   "HUB",   "HUE",   "HUG",   "HUH",   "HUM",   "HUT",
    "I",     "ICY",   "IDA",   "IF",    "IKE",   "ILL",   "INK",   "INN",
    "IO",    "ION",   "IQ",    "IRA",   "IRE",   "IRK",   "IS",    "IT",
    "ITS",   "IVY",   "JAB",   "JAG",   "JAM",   "JAN",   "JAR",   "JAW",
    "JAY",   "JET",   "JIG",   "JIM",   "JO",    "JOB",   "JOE",   "JOG",
    "JOT",   "JOY",   "JUG",   "JUT",   "KAY",   "KEG",   "KEN",   "KEY",
    "KID",   "KIM",   "KIN",   "KIT",   "LA",    "LAB",   "LAC",   "LAD",
    "LAG",   "LAM",   "LAP",   "LAW",   "LAY",   "LEA",   "LED",   "LEE",
    "LEG",   "LEN",   "LEO",   "LET",   "LEW",   "LID",   "LIE",   "LIN",
    "LIP",   "LIT",   "LO",    "LOB",   "LOG",   "LOP",   "LOS",   "LOT",
    "LOU",   "LOW",   "LOY",   "LUG",   "LYE",   "MA",    "MAC",   "MAD",
    "MAE",   "MAN",   "MAO",   "MAP",   "MAT",   "MAW",   "MAY",   "ME",
    "MEG",   "MEL",   "MEN",   "MET",   "MEW",   "MID",   "MIN",   "MIT",
    "MOB",   "MOD",   "MOE",   "MOO",   "MOP",   "MOS",   "MOT",   "MOW",
    "MUD",   "MUG",   "MUM",   "MY",    "NAB",   "NAG",   "NAN",   "NAP",
    "NAT",   "NAY",   "NE",    "NED",   "NEE",   "NET",   "NEW",   "NIB",
    "NIL",   "NIP",   "NIT",   "NO",    "NOB",   "NOD",   "NON",   "NOR",
    "NOT",   "NOV",   "NOW",   "NU",    "NUN",   "NUT",   "O",     "OAF",
    "OAK",   "OAR",   "OAT",   "ODD",   "ODE",   "OF",    "OFF",   "OFT",
    "OH",    "OIL",   "OK",    "OLD",   "ON",    "ONE",   "OR",    "ORB",
    "ORE",   "ORR",   "OS",    "OTT",   "OUR",   "OUT",   "OVA",   "OW",
    "OWE",   "OWL",   "OWN",   "OX",    "PA",    "PAD",   "PAL",   "PAM",
    "PAN",   "PAP",   "PAR",   "PAT",   "PAW",   "PAY",   "PEA",   "PEG",
    "PEN",   "PEP",   "PER",   "PET",   "PEW",   "PHI",   "PI",    "PIE",
    "PIN",   "PIT",   "PLY",   "PO",    "POD",   "POE",   "POP",   "POT",
    "POW",   "PRO",   "PRY",   "PUB",   "PUG",   "PUN",   "PUP",   "PUT",
    "QUO",   "RAG",   "RAM",   "RAN",   "RAP",   "RAT",   "RAW",   "RAY",
    "REB",   "RED",   "REP",   "RET",   "RIB",   "RID",   "RIG",   "RIM",
    "RIO",   "RIP",   "ROB",   "ROD",   "ROE",   "RON",   "ROT",   "ROW",
    "ROY",   "RUB",   "RUE",   "RUG",   "RUM",   "RUN",   "RYE",   "SAC",
    "SAD",   "SAG",   "SAL",   "SAM",   "SAN",   "SAP",   "SAT",   "SAW",
    "SAY",   "SEA",   "SEC",   "SEE",   "SEN",   "SET",   "SEW",   "SHE",
    "SHY",   "SIN",   "SIP",   "SIR",   "SIS",   "SIT",   "SKI",   "SKY",
    "SLY",   "SO",    "SOB",   "SOD",   "SON",   "SOP",   "SOW",   "SOY",
    "SPA",   "SPY",   "SUB",   "SUD",   "SUE",   "SUM",   "SUN",   "SUP",
    "TAB",   "TAD",   "TAG",   "TAN",   "TAP",   "TAR",   "TEA",   "TED",
    "TEE",   "TEN",   "THE",   "THY",   "TIC",   "TIE",   "TIM",   "TIN",
    "TIP",   "TO",    "TOE",   "TOG",   "TOM",   "TON",   "TOO",   "TOP",
    "TOW",   "TOY",   "TRY",   "TUB",   "TUG",   "TUM",   "TUN",   "TWO",
    "UN",    "UP",    "US",    "USE",   "VAN",   "VAT",   "VET",   "VIE",
    "WAD",   "WAG",   "WAR",   "WAS",   "WAY",   "WE",    "WEB",   "WED",
    "WEE",   "WET",   "WHO",   "WHY",   "WIN",   "WIT",   "WOK",   "WON",
    "WOO",   "WOW",   "WRY",   "WU",    "YAM",   "YAP",   "YAW",   "YE",
    "YEA",   "YES",   "YET",   "YOU",   "ABED",  "ABEL",  "ABET",  "ABLE",
    "ABUT",  "ACHE",  "ACID",  "ACME",  "ACRE",  "ACTA",  "ACTS",  "ADAM",
    "ADDS",  "ADEN",  "AFAR",  "AFRO",  "AGEE",  "AHEM",  "AHOY",  "AIDA",
    "AIDE",  "AIDS",  "AIRY",  "AJAR",  "AKIN",  "ALAN",  "ALEC",  "ALGA",
    "ALIA",  "ALLY",  "ALMA",  "ALOE",  "ALSO",  "ALTO",  "ALUM",  "ALVA",
    "AMEN",  "AMES",  "AMID",  "AMMO",  "AMOK",  "AMOS",  "AMRA",  "ANDY",
    "ANEW",  "ANNA",  "ANNE",  "ANTE",  "ANTI",  "AQUA",  "ARAB",  "ARCH",
    "AREA",  "ARGO",  "ARID",  "ARMY",  "ARTS",  "ARTY",  "ASIA",  "ASKS",
    "ATOM",  "AUNT",  "AURA",  "AUTO",  "AVER",  "AVID",  "AVIS",  "AVON",
    "AVOW",  "AWAY",  "AWRY",  "BABE",  "BABY",  "BACH",  "BACK",  "BADE",
    "BAIL",  "BAIT",  "BAKE",  "BALD",  "BALE",  "BALI",  "BALK",  "BALL",
    "BALM",  "BAND",  "BANE",  "BANG",  "BANK",  "BARB",  "BARD",  "BARE",
    "BARK",  "BARN",  "BARR",  "BASE",  "BASH",  "BASK",  "BASS",  "BATE",
    "BATH",  "BAWD",  "BAWL",  "BEAD",  "BEAK",  "BEAM",  "BEAN",  "BEAR",
    "BEAT",  "BEAU",  "BECK",  "BEEF",  "BEEN",  "BEER",  "BEET",  "BELA",
    "BELL",  "BELT",  "BEND",  "BENT",  "BERG",  "BERN",  "BERT",  "BESS",
    "BEST",  "BETA",  "BETH",  "BHOY",  "BIAS",  "BIDE",  "BIEN",  "BILE",
    "BILK",  "BILL",  "BIND",  "BING",  "BIRD",  "BITE",  "BITS",  "BLAB",
    "BLAT",  "BLED",  "BLEW",  "BLOB",  "BLOC",  "BLOT",  "BLOW",  "BLUE",
    "BLUM",  "BLUR",  "BOAR",  "BOAT",  "BOCA",  "BOCK",  "BODE",  "BODY",
    "BOGY",  "BOHR",  "BOIL",  "BOLD",  "BOLO",  "BOLT",  "BOMB",  "BONA",
    "BOND",  "BONE",  "BONG",  "BONN",  "BONY",  "BOOK",  "BOOM",  "BOON",
    "BOOT",  "BORE",  "BORG",  "BORN",  "BOSE",  "BOSS",  "BOTH",  "BOUT",
    "BOWL",  "BOYD",  "BRAD",  "BRAE",  "BRAG",  "BRAN",  "BRAY",  "BRED",
    "BREW",  "BRIG",  "BRIM",  "BROW",  "BUCK",  "BUDD",  "BUFF",  "BULB",
    "BULK",  "BULL",  "BUNK",  "BUNT",  "BUOY",  "BURG",  "BURL",  "BURN",
    "BURR",  "BURT",  "BURY",  "BUSH",  "BUSS",  "BUST",  "BUSY",  "BYTE",
    "CADY",  "CAFE",  "CAGE",  "CAIN",  "CAKE",  "CALF",  "CALL",  "CALM",
    "CAME",  "CANE",  "CANT",  "CARD",  "CARE",  "CARL",  "CARR",  "CART",
    "CASE",  "CASH",  "CASK",  "CAST",  "CAVE",  "CEIL",  "CELL",  "CENT",
    "CERN",  "CHAD",  "CHAR",  "CHAT",  "CHAW",  "CHEF",  "CHEN",  "CHEW",
    "CHIC",  "CHIN",  "CHOU",  "CHOW",  "CHUB",  "CHUG",  "CHUM",  "CITE",
    "CITY",  "CLAD",  "CLAM",  "CLAN",  "CLAW",  "CLAY",  "CLOD",  "CLOG",
    "CLOT",  "CLUB",  "CLUE",  "COAL",  "COAT",  "COCA",  "COCK",  "COCO",
    "CODA",  "CODE",  "CODY",  "COED",  "COIL",  "COIN",  "COKE",  "COLA",
    "COLD",  "COLT",  "COMA",  "COMB",  "COME",  "COOK",  "COOL",  "COON",
    "COOT",  "CORD",  "CORE",  "CORK",  "CORN",  "COST",  "COVE",  "COWL",
    "CRAB",  "CRAG",  "CRAM",  "CRAY",  "CREW",  "CRIB",  "CROW",  "CRUD",
    "CUBA",  "CUBE",  "CUFF",  "CULL",  "CULT",  "CUNY",  "CURB",  "CURD",
    "CURE",  "CURL",  "CURT",  "CUTS",  "DADE",  "DALE",  "DAME",  "DANA",
    "DANE",  "DANG",  "DANK",  "DARE",  "DARK",  "DARN",  "DART",  "DASH",
    "DATA",  "DATE",  "DAVE",  "DAVY",  "DAWN",  "DAYS",  "DEAD",  "DEAF",
    "DEAL",  "DEAN",  "DEAR",  "DEBT",  "DECK",  "DEED",  "DEEM",  "DEER",
    "DEFT",  "DEFY",  "DELL",  "DENT",  "DENY",  "DESK",  "DIAL",  "DICE",
    "DIED",  "DIET",  "DIME",  "DINE",  "DING",  "DINT",  "DIRE",  "DIRT",
    "DISC",  "DISH",  "DISK",  "DIVE",  "DOCK",  "DOES",  "DOLE",  "DOLL",
    "DOLT",  "DOME",  "DONE",  "DOOM",  "DOOR",  "DORA",  "DOSE",  "DOTE",
    "DOUG",  "DOUR",  "DOVE",  "DOWN",  "DRAB",  "DRAG",  "DRAM",  "DRAW",
    "DREW",  "DRUB",  "DRUG",  "DRUM",  "DUAL",  "DUCK",  "DUCT",  "DUEL",
    "DUET",  "DUKE",  "DULL",  "DUMB",  "DUNE",  "DUNK",  "DUSK",  "DUST",
    "DUTY",  "EACH",  "EARL",  "EARN",  "EASE",  "EAST",  "EASY",  "EBEN",
    "ECHO",  "EDDY",  "EDEN",  "EDGE",  "EDGY",  "EDIT",  "EDNA",  "EGAN",
    "ELAN",  "ELBA",  "ELLA",  "ELSE",  "EMIL",  "EMIT",  "EMMA",  "ENDS",
    "ERIC",  "EROS",  "EVEN",  "EVER",  "EVIL",  "EYED",  "FACE",  "FACT",
    "FADE",  "FAIL",  "FAIN",  "FAIR",  "FAKE",  "FALL",  "FAME",  "FANG",
    "FARM",  "FAST",  "FATE",  "FAWN",  "FEAR",  "FEAT",  "FEED",  "FEEL",
    "FEET",  "FELL",  "FELT",  "FEND",  "FERN",  "FEST",  "FEUD",  "FIEF",
    "FIGS",  "FILE",  "FILL",  "FILM",  "FIND",  "FINE",  "FINK",  "FIRE",
    "FIRM",  "FISH",  "FISK",  "FIST",  "FITS",  "FIVE",  "FLAG",  "FLAK",
    "FLAM",  "FLAT",  "FLAW",  "FLEA",  "FLED",  "FLEW",  "FLIT",  "FLOC",
    "FLOG",  "FLOW",  "FLUB",  "FLUE",  "FOAL",  "FOAM",  "FOGY",  "FOIL",
    "FOLD",  "FOLK",  "FOND",  "FONT",  "FOOD",  "FOOL",  "FOOT",  "FORD",
    "FORE",  "FORK",  "FORM",  "FORT",  "FOSS",  "FOUL",  "FOUR",  "FOWL",
    "FRAU",  "FRAY",  "FRED",  "FREE",  "FRET",  "FREY",  "FROG",  "FROM",
    "FUEL",  "FULL",  "FUME",  "FUND",  "FUNK",  "FURY",  "FUSE",  "FUSS",
    "GAFF",  "GAGE",  "GAIL",  "GAIN",  "GAIT",  "GALA",  "GALE",  "GALL",
    "GALT",  "GAME",  "GANG",  "GARB",  "GARY",  "GASH",  "GATE",  "GAUL",
    "GAUR",  "GAVE",  "GAWK",  "GEAR",  "GELD",  "GENE",  "GENT",  "GERM",
    "GETS",  "GIBE",  "GIFT",  "GILD",  "GILL",  "GILT",  "GINA",  "GIRD",
    "GIRL",  "GIST",  "GIVE",  "GLAD",  "GLEE",  "GLEN",  "GLIB",  "GLOB",
    "GLOM",  "GLOW",  "GLUE",  "GLUM",  "GLUT",  "GOAD",  "GOAL",  "GOAT",
    "GOER",  "GOES",  "GOLD",  "GOLF",  "GONE",  "GONG",  "GOOD",  "GOOF",
    "GORE",  "GORY",  "GOSH",  "GOUT",  "GOWN",  "GRAB",  "GRAD",  "GRAY",
    "GREG",  "GREW",  "GREY",  "GRID",  "GRIM",  "GRIN",  "GRIT",  "GROW",
    "GRUB",  "GULF",  "GULL",  "GUNK",  "GURU",  "GUSH",  "GUST",  "GWEN",
    "GWYN",  "HAAG",  "HAAS",  "HACK",  "HAIL",  "HAIR",  "HALE",  "HALF",
    "HALL",  "HALO",  "HALT",  "HAND",  "HANG",  "HANK",  "HANS",  "HARD",
    "HARK",  "HARM",  "HART",  "HASH",  "HAST",  "HATE",  "HATH",  "HAUL",
    "HAVE",  "HAWK",  "HAYS",  "HEAD",  "HEAL",  "HEAR",  "HEAT",  "HEBE",
    "HECK",  "HEED",  "HEEL",  "HEFT",  "HELD",  "HELL",  "HELM",  "HERB",
    "HERD",  "HERE",  "HERO",  "HERS",  "HESS",  "HEWN",  "HICK",  "HIDE",
    "HIGH",  "HIKE",  "HILL",  "HILT",  "HIND",  "HINT",  "HIRE",  "HISS",
    "HIVE",  "HOBO",  "HOCK",  "HOFF",  "HOLD",  "HOLE",  "HOLM",  "HOLT",
    "HOME",  "HONE",  "HONK",  "HOOD",  "HOOF",  "HOOK",  "HOOT",  "HORN",
    "HOSE",  "HOST",  "HOUR",  "HOVE",  "HOWE",  "HOWL",  "HOYT",  "HUCK",
    "HUED",  "HUFF",  "HUGE",  "HUGH",  "HUGO",  "HULK",  "HULL",  "HUNK",
    "HUNT",  "HURD",  "HURL",  "HURT",  "HUSH",  "HYDE",  "HYMN",  "IBIS",
    "ICON",  "IDEA",  "IDLE",  "IFFY",  "INCA",  "INCH",  "INTO",  "IONS",
    "IOTA",  "IOWA",  "IRIS",  "IRMA",  "IRON",  "ISLE",  "ITCH",  "ITEM",
    "IVAN",  "JACK",  "JADE",  "JAIL",  "JAKE",  "JANE",  "JAVA",  "JEAN",
    "JEFF",  "JERK",  "JESS",  "JEST",  "JIBE",  "JILL",  "JILT",  "JIVE",
    "JOAN",  "JOBS",  "JOCK",  "JOEL",  "JOEY",  "JOHN",  "JOIN",  "JOKE",
    "JOLT",  "JOVE",  "JUDD",  "JUDE",  "JUDO",  "JUDY",  "JUJU",  "JUKE",
    "JULY",  "JUNE",  "JUNK",  "JUNO",  "JURY",  "JUST",  "JUTE",  "KAHN",
    "KALE",  "KANE",  "KANT",  "KARL",  "KATE",  "KEEL",  "KEEN",  "KENO",
    "KENT",  "KERN",  "KERR",  "KEYS",  "KICK",  "KILL",  "KIND",  "KING",
    "KIRK",  "KISS",  "KITE",  "KLAN",  "KNEE",  "KNEW",  "KNIT",  "KNOB",
    "KNOT",  "KNOW",  "KOCH",  "KONG",  "KUDO",  "KURD",  "KURT",  "KYLE",
    "LACE",  "LACK",  "LACY",  "LADY",  "LAID",  "LAIN",  "LAIR",  "LAKE",
    "LAMB",  "LAME",  "LAND",  "LANE",  "LANG",  "LARD",  "LARK",  "LASS",
    "LAST",  "LATE",  "LAUD",  "LAVA",  "LAWN",  "LAWS",  "LAYS",  "LEAD",
    "LEAF",  "LEAK",  "LEAN",  "LEAR",  "LEEK",  "LEER",  "LEFT",  "LEND",
    "LENS",  "LENT",  "LEON",  "LESK",  "LESS",  "LEST",  "LETS",  "LIAR",
    "LICE",  "LICK",  "LIED",  "LIEN",  "LIES",  "LIEU",  "LIFE",  "LIFT",
    "LIKE",  "LILA",  "LILT",  "LILY",  "LIMA",  "LIMB",  "LIME",  "LIND",
    "LINE",  "LINK",  "LINT",  "LION",  "LISA",  "LIST",  "LIVE",  "LOAD",
    "LOAF",  "LOAM",  "LOAN",  "LOCK",  "LOFT",  "LOGE",  "LOIS",  "LOLA",
    "LONE",  "LONG",  "LOOK",  "LOON",  "LOOT",  "LORD",  "LORE",  "LOSE",
    "LOSS",  "LOST",  "LOUD",  "LOVE",  "LOWE",  "LUCK",  "LUCY",  "LUGE",
    "LUKE",  "LULU",  "LUND",  "LUNG",  "LURA",  "LURE",  "LURK",  "LUSH",
    "LUST",  "LYLE",  "LYNN",  "LYON",  "LYRA",  "MACE",  "MADE",  "MAGI",
    "MAID",  "MAIL",  "MAIN",  "MAKE",  "MALE",  "MALI",  "MALL",  "MALT",
    "MANA",  "MANN",  "MANY",  "MARC",  "MARE",  "MARK",  "MARS",  "MART",
    "MARY",  "MASH",  "MASK",  "MASS",  "MAST",  "MATE",  "MATH",  "MAUL",
    "MAYO",  "MEAD",  "MEAL",  "MEAN",  "MEAT",  "MEEK",  "MEET",  "MELD",
    "MELT",  "MEMO",  "MEND",  "MENU",  "MERT",  "MESH",  "MESS",  "MICE",
    "MIKE",  "MILD",  "MILE",  "MILK",  "MILL",  "MILT",  "MIMI",  "MIND",
    "MINE",  "MINI",  "MINK",  "MINT",  "MIRE",  "MISS",  "MIST",  "MITE",
    "MITT",  "MOAN",  "MOAT",  "MOCK",  "MODE",  "MOLD",  "MOLE",  "MOLL",
    "MOLT",  "MONA",  "MONK",  "MONT",  "MOOD",  "MOON",  "MOOR",  "MOOT",
    "MORE",  "MORN",  "MORT",  "MOSS",  "MOST",  "MOTH",  "MOVE",  "MUCH",
    "MUCK",  "MUDD",  "MUFF",  "MULE",  "MULL",  "MURK",  "MUSH",  "MUST",
    "MUTE",  "MUTT",  "MYRA",  "MYTH",  "NAGY",  "NAIL",  "NAIR",  "NAME",
    "NARY",  "NASH",  "NAVE",  "NAVY",  "NEAL",  "NEAR",  "NEAT",  "NECK",
    "NEED",  "NEIL",  "NELL",  "NEON",  "NERO",  "NESS",  "NEST",  "NEWS",
    "NEWT",  "NIBS",  "NICE",  "NICK",  "NILE",  "NINA",  "NINE",  "NOAH",
    "NODE",  "NOEL",  "NOLL",  "NONE",  "NOOK",  "NOON",  "NORM",  "NOSE",
    "NOTE",  "NOUN",  "NOVA",  "NUDE",  "NULL",  "NUMB",  "OATH",  "OBEY",
    "OBOE",  "ODIN",  "OHIO",  "OILY",  "OINT",  "OKAY",  "OLAF",  "OLDY",
    "OLGA",  "OLIN",  "OMAN",  "OMEN",  "OMIT",  "ONCE",  "ONES",  "ONLY",
    "ONTO",  "ONUS",  "ORAL",  "ORGY",  "OSLO",  "OTIS",  "OTTO",  "OUCH",
    "OUST",  "OUTS",  "OVAL",  "OVEN",  "OVER",  "OWLY",  "OWNS",  "QUAD",
    "QUIT",  "QUOD",  "RACE",  "RACK",  "RACY",  "RAFT",  "RAGE",  "RAID",
    "RAIL",  "RAIN",  "RAKE",  "RANK",  "RANT",  "RARE",  "RASH",  "RATE",
    "RAVE",  "RAYS",  "READ",  "REAL",  "REAM",  "REAR",  "RECK",  "REED",
    "REEF",  "REEK",  "REEL",  "REID",  "REIN",  "RENA",  "REND",  "RENT",
    "REST",  "RICE",  "RICH",  "RICK",  "RIDE",  "RIFT",  "RILL",  "RIME",
    "RING",  "RINK",  "RISE",  "RISK",  "RITE",  "ROAD",  "ROAM",  "ROAR",
    "ROBE",  "ROCK",  "RODE",  "ROIL",  "ROLL",  "ROME",  "ROOD",  "ROOF",
    "ROOK",  "ROOM",  "ROOT",  "ROSA",  "ROSE",  "ROSS",  "ROSY",  "ROTH",
    "ROUT",  "ROVE",  "ROWE",  "ROWS",  "RUBE",  "RUBY",  "RUDE",  "RUDY",
    "RUIN",  "RULE",  "RUNG",  "RUNS",  "RUNT",  "RUSE",  "RUSH",  "RUSK",
    "RUSS",  "RUST",  "RUTH",  "SACK",  "SAFE",  "SAGE",  "SAID",  "SAIL",
    "SALE",  "SALK",  "SALT",  "SAME",  "SAND",  "SANE",  "SANG",  "SANK",
    "SARA",  "SAUL",  "SAVE",  "SAYS",  "SCAN",  "SCAR",  "SCAT",  "SCOT",
    "SEAL",  "SEAM",  "SEAR",  "SEAT",  "SEED",  "SEEK",  "SEEM",  "SEEN",
    "SEES",  "SELF",  "SELL",  "SEND",  "SENT",  "SETS",  "SEWN",  "SHAG",
    "SHAM",  "SHAW",  "SHAY",  "SHED",  "SHIM",  "SHIN",  "SHOD",  "SHOE",
    "SHOT",  "SHOW",  "SHUN",  "SHUT",  "SICK",  "SIDE",  "SIFT",  "SIGH",
    "SIGN",  "SILK",  "SILL",  "SILO",  "SILT",  "SINE",  "SING",  "SINK",
    "SIRE",  "SITE",  "SITS",  "SITU",  "SKAT",  "SKEW",  "SKID",  "SKIM",
    "SKIN",  "SKIT",  "SLAB",  "SLAM",  "SLAT",  "SLAY",  "SLED",  "SLEW",
    "SLID",  "SLIM",  "SLIT",  "SLOB",  "SLOG",  "SLOT",  "SLOW",  "SLUG",
    "SLUM",  "SLUR",  "SMOG",  "SMUG",  "SNAG",  "SNOB",  "SNOW",  "SNUB",
    "SNUG",  "SOAK",  "SOAR",  "SOCK",  "SODA",  "SOFA",  "SOFT",  "SOIL",
    "SOLD",  "SOME",  "SONG",  "SOON",  "SOOT",  "SORE",  "SORT",  "SOUL",
    "SOUR",  "SOWN",  "STAB",  "STAG",  "STAN",  "STAR",  "STAY",  "STEM",
    "STEW",  "STIR",  "STOW",  "STUB",  "STUN",  "SUCH",  "SUDS",  "SUIT",
    "SULK",  "SUMS",  "SUNG",  "SUNK",  "SURE",  "SURF",  "SWAB",  "SWAG",
    "SWAM",  "SWAN",  "SWAT",  "SWAY",  "SWIM",  "SWUM",  "TACK",  "TACT",
    "TAIL",  "TAKE",  "TALE",  "TALK",  "TALL",  "TANK",  "TASK",  "TATE",
    "TAUT",  "TEAL",  "TEAM",  "TEAR",  "TECH",  "TEEM",  "TEEN",  "TEET",
    "TELL",  "TEND",  "TENT",  "TERM",  "TERN",  "TESS",  "TEST",  "THAN",
    "THAT",  "THEE",  "THEM",  "THEN",  "THEY",  "THIN",  "THIS",  "THUD",
    "THUG",  "TICK",  "TIDE",  "TIDY",  "TIED",  "TIER",  "TILE",  "TILL",
    "TILT",  "TIME",  "TINA",  "TINE",  "TINT",  "TINY",  "TIRE",  "TOAD",
    "TOGO",  "TOIL",  "TOLD",  "TOLL",  "TONE",  "TONG",  "TONY",  "TOOK",
    "TOOL",  "TOOT",  "TORE",  "TORN",  "TOTE",  "TOUR",  "TOUT",  "TOWN",
    "TRAG",  "TRAM",  "TRAY",  "TREE",  "TREK",  "TRIG",  "TRIM",  "TRIO",
    "TROD",  "TROT",  "TROY",  "TRUE",  "TUBA",  "TUBE",  "TUCK",  "TUFT",
    "TUNA",  "TUNE",  "TUNG",  "TURF",  "TURN",  "TUSK",  "TWIG",  "TWIN",
    "TWIT",  "ULAN",  "UNIT",  "URGE",  "USED",  "USER",  "USES",  "UTAH",
    "VAIL",  "VAIN",  "VALE",  "VARY",  "VASE",  "VAST",  "VEAL",  "VEDA",
    "VEIL",  "VEIN",  "VEND",  "VENT",  "VERB",  "VERY",  "VETO",  "VICE",
    "VIEW",  "VINE",  "VISE",  "VOID",  "VOLT",  "VOTE",  "WACK",  "WADE",
    "WAGE",  "WAIL",  "WAIT",  "WAKE",  "WALE",  "WALK",  "WALL",  "WALT",
    "WAND",  "WANE",  "WANG",  "WANT",  "WARD",  "WARM",  "WARN",  "WART",
    "WASH",  "WAST",  "WATS",  "WATT",  "WAVE",  "WAVY",  "WAYS",  "WEAK",
    "WEAL",  "WEAN",  "WEAR",  "WEED",  "WEEK",  "WEIR",  "WELD",  "WELL",
    "WELT",  "WENT",  "WERE",  "WERT",  "WEST",  "WHAM",  "WHAT",  "WHEE",
    "WHEN",  "WHET",  "WHOA",  "WHOM",  "WICK",  "WIFE",  "WILD",  "WILL",
    "WIND",  "WINE",  "WING",  "WINK",  "WINO",  "WIRE",  "WISE",  "WISH",
    "WITH",  "WOLF",  "WONT",  "WOOD",  "WOOL",  "WORD",  "WORE",  "WORK",
    "WORM",  "WORN",  "WOVE",  "WRIT",  "WYNN",  "YALE",  "YANG",  "YANK",
    "YARD",  "YARN",  "YAWL",  "YAWN",  "YEAH",  "YEAR",  "YELL",  "YOGA",
    "YOKE",
];


/// Folds an arbitrary-length input (greater than 8 bytes) to 8 bytes according
/// to the algorithm in Appendix A of
/// [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
#[cfg(any(feature = "md4", feature = "md5"))]
pub fn fold_md (input: &mut [u8]) {
    let mut j = 0;
    for i in 8..input.len() {
        input[j] ^= input[i];
        j = (j + 1) % 8;
    }
}

/// See Appendix A of [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
/// 
/// Note that the example code in this appendix makes reference to some ancient
/// SHA-1 library: particularly the `SHA_INFO` struct. This struct outputs the
/// digest into the `digest` field, which is defined as an array of five
/// `uint32`s. Since the Rust SHA1 library outputs the digest into a 20-byte
/// array instead, this implementation differs slightly in this regard.
#[cfg(feature = "sha1")]
pub fn fold_sha1 (digest: &mut [u8; 20]) {
    fold_md(&mut digest[..]);
    digest.swap(0, 3);
    digest.swap(1, 2);
    digest.swap(4, 7);
    digest.swap(5, 6);
}

const INIT_SIX_WORDS: [&'static str; 6] = [ "A", "A", "A", "A", "A", "A" ];

/// Calculate the checksum, per section 6.0 of
/// [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
pub fn calculate_checksum (input: &[u8; 8]) -> u64 {
    input
        .iter()
        .map(|num| -> u64 {
            let n = *num;
            ((n & 0b0000_0011)
            + ((n & 0b0000_1100) >> 2)
            + ((n & 0b0011_0000) >> 4)
            + ((n & 0b1100_0000) >> 6)).into()
        })
        .reduce(|acc, curr| acc + curr)
        .unwrap()
        & 0b11
}

/// Encode a 64-bit value using the standard dictionary words defined in
/// [IETF RFC 1760](https://www.rfc-editor.org/rfc/rfc1760) for use in S/KEY,
/// and used OTP in
/// [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
/// 
/// The inverse of [decode_word_format_with_std_dict].
#[cfg(feature = "words")]
pub fn convert_to_word_format (result: &[u8; 8]) -> [&'static str; 6] {
    let checksum: u64 = calculate_checksum(result);
    let mut result = u64::from_be_bytes(*result);
    let mut output: [&'static str; 6] = INIT_SIX_WORDS;
    for i in 0..5 {
        let bits = (result & (0b11111111111 << (64 - 11))) >> (64 - 11); // 11 bits
        output[i] = STANDARD_DICTIONARY[bits as usize];
        result = result.wrapping_shl(11);
    }
    let bits: u64 = ((result & (0b11111111111 << (64 - 11))) >> (64 - 11)) + checksum; // 11 bits
    output[5] = STANDARD_DICTIONARY[bits as usize];
    output
}

/// Decode a 64-bit value using the standard dictionary words defined in
/// [IETF RFC 1760](https://www.rfc-editor.org/rfc/rfc1760) for use in S/KEY,
/// and used OTP in
/// [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
///
/// Returns `None` if a word does not appear in the standard dictionary.
/// Otherwise, returns the decoded bytes and a `bool` indicating whether the
/// checksum was valid, respectively.
///
/// The inverse of [convert_to_word_format].
#[cfg(feature = "words")]
pub fn decode_word_format_with_std_dict (words: [&str; 6]) -> Option<([u8; 8], bool)> {
    let mut output: u64 = 0;
    for word in words.iter().take(5) {
        let bits = STANDARD_DICTIONARY.iter().position(|w| *w == *word)?;
        output <<= 11;
        output |= bits as u64;
    }
    // The last word has special treatment: it's two final bits are a checksum.
    let bits = STANDARD_DICTIONARY.iter().position(|w| *w == words[5])?;
    output <<= 9;
    output |= bits as u64 / 4; // mod by 2^9 just to make sure we don't add checksum bits
    let checksum_bits = bits as u64 % 4;
    let output = output.to_be_bytes();
    let checksum: u64 = calculate_checksum(&output);
    Some((output, checksum_bits == checksum))
}

// TODO: Move to documentation


/// A parsed OTP challenge string per Section 2.1 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
#[derive(Debug)]
pub struct OTPChallenge <'a> {
    pub hash_alg: &'a str,
    pub hash_count: usize,
    pub seed: &'a str,
}

/// A parsed OTP init string per Section 4.1 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
pub fn parse_otp_challenge <'a> (s: &'a str) -> Option<OTPChallenge<'a>> {
    if s.len() < 9 { // This is the smallest that an OTP challenge can be.
        return None;
    }
    if s.len() > 128 {
        return None; // To prevent denial of service via outrageous values.
    }
    if !s.starts_with("otp-") {
        return None;
    }
    let x = &s[4..];
    let mut hash_alg: Option<&'a str> = None;
    let mut seed: Option<&'a str> = None;
    let mut count: Option<usize> = None;
    for token in x.split_ascii_whitespace() {
        if hash_alg.is_none() {
            hash_alg = Some(token);
        }
        else if count.is_none() {
            count = Some(usize::from_str_radix(token, 10).ok()?);
        }
        else if seed.is_none() {
            seed = Some(token);
            break;
        }
    }
    Some(OTPChallenge{
        hash_alg: hash_alg?,
        seed: seed?,
        hash_count: count?,
    })
}

pub type Hex64Bit = [u8; 8];

/// A Hex value or dictionary words
#[cfg(feature = "parsing")]
#[derive(Debug, PartialEq, Eq)]
pub enum HexOrWords <'a> {
    Hex(Hex64Bit),
    Words(&'a str),
}

impl HexOrWords<'_> {

    pub fn try_into_bytes (&self) -> Option<[u8; 8]> {
        match self {
            HexOrWords::Hex(h) => Some(h.to_owned()),
            HexOrWords::Words(w) => {
                let mut w = w.split_ascii_whitespace();
                let six_words = [ w.next(), w.next(), w.next(), w.next(), w.next(), w.next() ];
                if six_words[5].is_none() {
                    return None;
                }
                if w.next().is_some() {
                    return None;
                }
                let six_words = [
                    six_words[0].unwrap(),
                    six_words[1].unwrap(),
                    six_words[2].unwrap(),
                    six_words[3].unwrap(),
                    six_words[4].unwrap(),
                    six_words[5].unwrap(),
                ];
                let maybe_64bits = decode_word_format_with_std_dict(six_words);
                if maybe_64bits.is_none() {
                    return None;
                }
                let (v, valid_checksum) = maybe_64bits.unwrap();
                if !valid_checksum {
                    return None;
                }
                Some(v)
            },
        }
    }

}

/// A parsed OTP init string per Section 4.1 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
#[derive(Debug)]
pub struct OTPInit <'a> {
    pub current_otp: HexOrWords<'a>,
    pub new_otp: HexOrWords<'a>,
    pub new_alg: &'a str,
    pub new_seq_num: usize,
    pub new_seed: &'a str,
}

/// A parsed OTP response per Sections 3 and 4 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
#[derive(Debug)]
pub enum OTPResponse <'a> {
    Init(OTPInit <'a>),
    Current(HexOrWords<'a>)
}

/// Parse OTP `init-hex-response` per Section 4.1 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
fn parse_otp_init_hex <'a> (s: &'a str) -> Option<OTPInit<'a>> {
    let mut sections = s.split(":");
    let current_otp = sections.next()?.cow_replace(" ", "");
    let new_params = sections.next()?;
    let new_otp = sections.next()?.cow_replace(" ", "");
    if sections.next().is_some() {
        return None;
    }
    let current_otp = <Hex64Bit>::from_hex(current_otp.cow_replace("\t", "").as_ref()).ok()?;
    let new_otp = <Hex64Bit>::from_hex(new_otp.cow_replace("\t", "").as_ref()).ok()?;
    let mut params = new_params.split(" ");
    let algorithm = params.next()?;
    let sequence_number = params.next()?;
    let seed = params.next()?;
    let sequence_number = <usize>::from_str_radix(sequence_number, 10).ok()?;
    Some(OTPInit {
        current_otp: HexOrWords::Hex(current_otp),
        new_otp: HexOrWords::Hex(new_otp),
        new_alg: algorithm,
        new_seq_num: sequence_number,
        new_seed: seed,
    })
}

/// Parse OTP `init-word-response` per Section 4.1 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
fn parse_otp_init_word <'a> (s: &'a str) -> Option<OTPInit<'a>> {
    let mut sections = s.split(":");
    let current_otp = sections.next()?;
    let new_params = sections.next()?;
    let new_otp = sections.next()?;
    if sections.next().is_some() {
        return None;
    }
    let mut params = new_params.split(" ");
    let algorithm = params.next()?;
    let sequence_number = params.next()?;
    let seed = params.next()?;
    let sequence_number = <usize>::from_str_radix(sequence_number, 10).ok()?;
    Some(OTPInit {
        current_otp: HexOrWords::Words(current_otp),
        new_otp: HexOrWords::Words(new_otp),
        new_alg: algorithm,
        new_seq_num: sequence_number,
        new_seed: seed,
    })
}

/// Parse OTP init strings per Section 4.1 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
pub fn parse_otp_init <'a> (s: &'a str) -> Option<OTPInit<'a>> {
    if s.len() <= 50 || s.len() > 100 { // Arbitrary upper limit
        return None;
    }
    if s.starts_with("init-hex:") {
        parse_otp_init_hex(&s[9..])
    }
    else if s.starts_with("init-word:") {
        parse_otp_init_word(&s[10..])
    }
    else {
        None
    }
}

/// Parse OTP response strings per Sections 3 and 4 of
/// [IETF RFC 2243](https://www.rfc-editor.org/rfc/rfc2243).
#[cfg(feature = "parsing")]
pub fn parse_otp_response <'a> (s: &'a str) -> Option<OTPResponse<'a>> {
    if s.len() < 20 || s.len() > 100 { // Arbitrary upper limit
        return None;
    }
    if s.starts_with("hex:") {
        let h = <Hex64Bit>::from_hex(&s[4..].cow_replace(" ", "").cow_replace("\t", "").as_ref()).ok()?;
        Some(OTPResponse::Current(HexOrWords::Hex(h)))
    }
    else if s.starts_with("word:") {
        Some(OTPResponse::Current(HexOrWords::Words(&s[5..])))
    }
    else if s.starts_with("init-hex:") {
        parse_otp_init_hex(&s[9..]).map(|i| OTPResponse::Init(i))
    }
    else if s.starts_with("init-word:") {
        parse_otp_init_word(&s[10..]).map(|i| OTPResponse::Init(i))
    }
    else {
        None
    }
}

/// Calculates the One-Time Pad using an arbitrary dynamic digest object
#[cfg(feature = "dyndig")]
fn calculate_otp_via_digest (
    hasher: &mut dyn digest::DynDigest,
    passphrase: &str,
    seed: &str,
    count: usize,
) -> [u8; 8] {
    hasher.update(seed.as_bytes());
    hasher.update(passphrase.as_bytes());
    let mut digest_bytes: [u8; 64] = [0; 64]; // Will accommodate a theoretical SHA-1024.
    hasher.finalize_into_reset(digest_bytes.as_mut_slice()).expect("hash size too large");
    fold_md(&mut digest_bytes);
    let mut prev_hash = digest_bytes;
    for _ in 0..count {
        hasher.update(&prev_hash[0..hasher.output_size()]);
        hasher.finalize_into_reset(digest_bytes.as_mut_slice()).expect("hash size too large");
        fold_md(&mut digest_bytes[0..hasher.output_size()]);
        prev_hash = digest_bytes;
    }
    [
        prev_hash[0],
        prev_hash[1],
        prev_hash[2],
        prev_hash[3],
        prev_hash[4],
        prev_hash[5],
        prev_hash[6],
        prev_hash[7],
    ]
}

/// Calculates the One-Time Pad using the `md4` algorithm.
#[cfg(feature = "md4")]
pub fn calculate_md4_otp (
    passphrase: &str,
    lowercased_seed: &str,
    count: usize,
) -> Option<[u8; 8]> {
    let mut m = Md4::new();
    m.update(lowercased_seed.as_bytes());
    m.update(passphrase.as_bytes());
    let mut digest_bytes = m.finalize();
    fold_md(&mut digest_bytes);
    let mut prev_hash = digest_bytes;
    for _ in 0..count {
        let mut m = Md4::new();
        m.update(&prev_hash[0..8]);
        let mut digest_bytes = m.finalize();
        fold_md(&mut digest_bytes);
        prev_hash = digest_bytes;
    }
    Some([
        prev_hash[0],
        prev_hash[1],
        prev_hash[2],
        prev_hash[3],
        prev_hash[4],
        prev_hash[5],
        prev_hash[6],
        prev_hash[7],
    ])
}

/// Calculates the One-Time Pad using the `md5` algorithm.
#[cfg(feature = "md5")]
pub fn calculate_md5_otp (
    passphrase: &str,
    lowercased_seed: &str,
    count: usize,
) -> Option<[u8; 8]> {
    let digest = md5::compute([
        lowercased_seed.as_ref(),
        passphrase,
    ].concat());
    let mut digest_bytes = digest.0;
    fold_md(&mut digest_bytes);
    let mut prev_hash = digest_bytes;
    for _ in 0..count {
        let mut digest_bytes = md5::compute(&prev_hash[0..8]).0;
        fold_md(&mut digest_bytes);
        prev_hash = digest_bytes;
    }
    Some([
        prev_hash[0],
        prev_hash[1],
        prev_hash[2],
        prev_hash[3],
        prev_hash[4],
        prev_hash[5],
        prev_hash[6],
        prev_hash[7],
    ])
}

/// Calculates the One-Time Pad using the `sha1` algorithm.
#[cfg(feature = "sha1")]
pub fn calculate_sha1_otp (
    passphrase: &str,
    lowercased_seed: &str,
    count: usize,
) -> Option<[u8; 8]> {
    let mut m = sha1_smol::Sha1::new();
    m.update(lowercased_seed.as_bytes());
    m.update(passphrase.as_bytes());
    let mut digest_bytes = m.digest().bytes();
    fold_sha1(&mut digest_bytes);
    let mut prev_hash = digest_bytes;
    for _ in 0..count {
        let mut m = sha1_smol::Sha1::new();
        m.update(&prev_hash[0..8]);
        let mut digest_bytes = m.digest().bytes();
        fold_sha1(&mut digest_bytes);
        prev_hash = digest_bytes;
    }
    Some([
        prev_hash[0],
        prev_hash[1],
        prev_hash[2],
        prev_hash[3],
        prev_hash[4],
        prev_hash[5],
        prev_hash[6],
        prev_hash[7],
    ])
}

/// Calculate an OTP value from supplied parameters, per Section 6.0 of
/// [IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html).
///
/// Returns `None` if the algorithm is not understood.
/// 
/// The `maybe_get_digest` function is a function that takes a digest name and
/// returns a corresponding `DynDigest`. This is so the types of hash algorithms
/// supported can be extended. This argument is only present if the `dyndig`
/// feature flag is enabled.
pub fn calculate_otp (
    hash_alg: &str,
    passphrase: &str,
    seed: &str,
    count: usize,
    #[cfg(feature = "dyndig")]
    maybe_get_digest: Option<fn(&str) -> Option<Box<dyn digest::DynDigest>>>,
) -> Option<[u8; 8]> {
    let lowercased_seed = seed.cow_to_ascii_lowercase();
    match hash_alg {
        #[cfg(feature = "md4")]
        "md4" => calculate_md4_otp(passphrase, lowercased_seed.as_ref(), count),
        #[cfg(feature = "md5")]
        "md5" => calculate_md5_otp(passphrase, lowercased_seed.as_ref(), count),
        #[cfg(feature = "sha1")]
        "sha1" => calculate_sha1_otp(passphrase, lowercased_seed.as_ref(), count),
        #[cfg(feature = "dyndig")]
        _ => {
            let get_digest = maybe_get_digest?;
            let mut digest = get_digest(hash_alg)?;
            Some(calculate_otp_via_digest(digest.as_mut(), passphrase, lowercased_seed.as_ref(), count))
        },
        #[cfg(not(feature = "dyndig"))]
        _ => {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Test folding

    type TestCase = (&'static str, &'static str, usize, [u8; 8], &'static str);

    const OFFICIAL_MD4_TEST_CASES: [TestCase; 9] = [
        ("This is a test.", "TeSt",      0, [ 0xD1, 0x85, 0x42, 0x18, 0xEB, 0xBB, 0x0B, 0x51 ], "ROME MUG FRED SCAN LIVE LACE"),
        ("This is a test.", "TeSt",      1, [ 0x63, 0x47, 0x3E, 0xF0, 0x1C, 0xD0, 0xB4, 0x44 ], "CARD SAD MINI RYE COL KIN"),
        ("This is a test.", "TeSt",     99, [ 0xC5, 0xE6, 0x12, 0x77, 0x6E, 0x6C, 0x23, 0x7A ], "NOTE OUT IBIS SINK NAVE MODE"),
        ("AbCdEfGhIjK", "alpha1",        0, [ 0x50, 0x07, 0x6F, 0x47, 0xEB, 0x1A, 0xDE, 0x4E ], "AWAY SEN ROOK SALT LICE MAP"),
        ("AbCdEfGhIjK", "alpha1",        1, [ 0x65, 0xD2, 0x0D, 0x19, 0x49, 0xB5, 0xF7, 0xAB ], "CHEW GRIM WU HANG BUCK SAID"),
        ("AbCdEfGhIjK", "alpha1",       99, [ 0xD1, 0x50, 0xC8, 0x2C, 0xCE, 0x6F, 0x62, 0xD1 ], "ROIL FREE COG HUNK WAIT COCA"),
        ("OTP's are good", "correct",    0, [ 0x84, 0x9C, 0x79, 0xD4, 0xF6, 0xF5, 0x53, 0x88 ], "FOOL STEM DONE TOOL BECK NILE"),
        ("OTP's are good", "correct",    1, [ 0x8C, 0x09, 0x92, 0xFB, 0x25, 0x08, 0x47, 0xB1 ], "GIST AMOS MOOT AIDS FOOD SEEM"),
        ("OTP's are good", "correct",   99, [ 0x3F, 0x3B, 0xF4, 0xB4, 0x14, 0x5F, 0xD7, 0x4B ], "TAG SLOW NOV MIN WOOL KENO"),
    ];

    const OFFICIAL_MD5_TEST_CASES: [TestCase; 9] = [
        ("This is a test.", "TeSt",      0, [ 0x9E, 0x87, 0x61, 0x34, 0xD9, 0x04, 0x99, 0xDD ], "INCH SEA ANNE LONG AHEM TOUR"),
        ("This is a test.", "TeSt",      1, [ 0x79, 0x65, 0xE0, 0x54, 0x36, 0xF5, 0x02, 0x9F ], "EASE OIL FUM CURE AWRY AVIS"),
        ("This is a test.", "TeSt",     99, [ 0x50, 0xFE, 0x19, 0x62, 0xC4, 0x96, 0x58, 0x80 ], "BAIL TUFT BITS GANG CHEF THY"),
        ("AbCdEfGhIjK", "alpha1",        0, [ 0x87, 0x06, 0x6D, 0xD9, 0x64, 0x4B, 0xF2, 0x06 ], "FULL PEW DOWN ONCE MORT ARC"),
        ("AbCdEfGhIjK", "alpha1",        1, [ 0x7C, 0xD3, 0x4C, 0x10, 0x40, 0xAD, 0xD1, 0x4B ], "FACT HOOF AT FIST SITE KENT"),
        ("AbCdEfGhIjK", "alpha1",       99, [ 0x5A, 0xA3, 0x7A, 0x81, 0xF2, 0x12, 0x14, 0x6C ], "BODE HOP JAKE STOW JUT RAP"),
        ("OTP's are good", "correct",    0, [ 0xF2, 0x05, 0x75, 0x39, 0x43, 0xDE, 0x4C, 0xF9 ], "ULAN NEW ARMY FUSE SUIT EYED"),
        ("OTP's are good", "correct",    1, [ 0xDD, 0xCD, 0xAC, 0x95, 0x6F, 0x23, 0x49, 0x37 ], "SKIM CULT LOB SLAM POE HOWL"),
        ("OTP's are good", "correct",   99, [ 0xB2, 0x03, 0xE2, 0x8F, 0xA5, 0x25, 0xBE, 0x47 ], "LONG IVY JULY AJAR BOND LEE"),
    ];

    const OFFICIAL_SHA1_TEST_CASES: [TestCase; 9] = [
        ("This is a test.", "TeSt",      0, [ 0xBB, 0x9E, 0x6A, 0xE1, 0x97, 0x9D, 0x8F, 0xF4 ], "MILT VARY MAST OK SEES WENT"),
        ("This is a test.", "TeSt",      1, [ 0x63, 0xD9, 0x36, 0x63, 0x97, 0x34, 0x38, 0x5B ], "CART OTTO HIVE ODE VAT NUT"),
        ("This is a test.", "TeSt",     99, [ 0x87, 0xFE, 0xC7, 0x76, 0x8B, 0x73, 0xCC, 0xF9 ], "GAFF WAIT SKID GIG SKY EYED"),
        ("AbCdEfGhIjK", "alpha1",        0, [ 0xAD, 0x85, 0xF6, 0x58, 0xEB, 0xE3, 0x83, 0xC9 ], "LEST OR HEEL SCOT ROB SUIT"),
        ("AbCdEfGhIjK", "alpha1",        1, [ 0xD0, 0x7C, 0xE2, 0x29, 0xB5, 0xCF, 0x11, 0x9B ], "RITE TAKE GELD COST TUNE RECK"),
        ("AbCdEfGhIjK", "alpha1",       99, [ 0x27, 0xBC, 0x71, 0x03, 0x5A, 0xAF, 0x3D, 0xC6 ], "MAY STAR TIN LYON VEDA STAN"),
        ("OTP's are good", "correct",    0, [ 0xD5, 0x1F, 0x3E, 0x99, 0xBF, 0x8E, 0x6F, 0x0B ], "RUST WELT KICK FELL TAIL FRAU"),
        ("OTP's are good", "correct",    1, [ 0x82, 0xAE, 0xB5, 0x2D, 0x94, 0x37, 0x74, 0xE4 ], "FLIT DOSE ALSO MEW DRUM DEFY"),
        ("OTP's are good", "correct",   99, [ 0x4F, 0x29, 0x6A, 0x74, 0xFE, 0x15, 0x67, 0xEC ], "AURA ALOE HURL WING BERG WAIT"),
    ];

    #[test]
    #[cfg(all(feature = "md4", feature = "words"))]
    fn passes_official_md4_test_cases() {
        for test_case in OFFICIAL_MD4_TEST_CASES {
            let otp = calculate_otp("md4", test_case.0, test_case.1, test_case.2, None).unwrap();
            assert_eq!(otp, test_case.3);
            let words = convert_to_word_format(&otp);
            assert_eq!(words.join(" "), test_case.4);
        }
    }

    #[test]
    #[cfg(all(feature = "md5", feature = "words"))]
    fn passes_official_md5_test_cases() {
        for test_case in OFFICIAL_MD5_TEST_CASES {
            let otp = calculate_otp("md5", test_case.0, test_case.1, test_case.2, None).unwrap();
            assert_eq!(otp, test_case.3);
            let words = convert_to_word_format(&otp);
            assert_eq!(words.join(" "), test_case.4);
        }
    }

    #[test]
    #[cfg(all(feature = "sha1", feature = "words"))]
    fn passes_official_sha1_test_cases() {
        for test_case in OFFICIAL_SHA1_TEST_CASES {
            let otp = calculate_otp("sha1", test_case.0, test_case.1, test_case.2, None).unwrap();
            assert_eq!(otp, test_case.3);
            let words = convert_to_word_format(&otp);
            assert_eq!(words.join(" "), test_case.4);
            let decoded = decode_word_format_with_std_dict(words).unwrap();
            assert_eq!(decoded, (test_case.3, true));
        }
    }

    #[test]
    #[cfg(feature = "parsing")]
    fn parses_otp_challenge() {
        let challenge = "otp-md5 487 dog2";
        let challenge = parse_otp_challenge(challenge).unwrap();
        assert_eq!(challenge.hash_alg, "md5");
        assert_eq!(challenge.hash_count, 487);
        assert_eq!(challenge.seed, "dog2");
    }

    #[test]
    #[cfg(feature = "parsing")]
    fn parses_otp_response_hex () {
        let otp_response = "hex:5Bf0 75d9 959d 036f";
        let r = parse_otp_response(&otp_response).unwrap();
        if let OTPResponse::Current(x) = r {
            if let HexOrWords::Hex(h) = x {
                assert_eq!(h, [ 0x5B, 0xf0, 0x75, 0xd9, 0x95, 0x9d, 0x03, 0x6f ]);
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    #[cfg(feature = "parsing")]
    fn parses_otp_response_word () {
        let otp_response = "word:BOND FOGY DRAB NE RISE MART";
        let r = parse_otp_response(&otp_response).unwrap();
        if let OTPResponse::Current(x) = r {
            if let HexOrWords::Words(w) = x {
                assert_eq!(w, "BOND FOGY DRAB NE RISE MART");
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    #[cfg(feature = "parsing")]
    fn parses_otp_response_init_hex () {
        let otp_response = "init-hex:5bf0 75d9 959d 036f:md5 499 ke1235:3712 dcb4 aa53 16c1";
        let r = parse_otp_response(&otp_response).unwrap();
        if let OTPResponse::Init(x) = r {
            assert_eq!(x.current_otp, HexOrWords::Hex([ 0x5B, 0xf0, 0x75, 0xd9, 0x95, 0x9d, 0x03, 0x6f ]));
            assert_eq!(x.new_otp, HexOrWords::Hex([ 0x37, 0x12, 0xdc, 0xb4, 0xaa, 0x53, 0x16, 0xc1 ]));
            assert_eq!(x.new_alg, "md5");
            assert_eq!(x.new_seq_num, 499);
            assert_eq!(x.new_seed, "ke1235");
        } else {
            panic!()
        }
    }

    #[test]
    #[cfg(feature = "parsing")]
    fn parses_otp_response_init_word () {
        let otp_response = "init-word:BOND FOGY DRAB NE RISE MART:md5 499 ke1235:RED HERD NOW BEAN PA BURG";
        let r = parse_otp_response(&otp_response).unwrap();
        if let OTPResponse::Init(x) = r {
            assert_eq!(x.current_otp, HexOrWords::Words("BOND FOGY DRAB NE RISE MART"));
            assert_eq!(x.new_otp, HexOrWords::Words("RED HERD NOW BEAN PA BURG"));
            assert_eq!(x.new_alg, "md5");
            assert_eq!(x.new_seq_num, 499);
            assert_eq!(x.new_seed, "ke1235");
        } else {
            panic!()
        }
    }
}
