#!/usr/bin/env python3
"""KeepCrypt offline verifier (M1 seed).

Python 3.9+, standard library only, one file. It never generates secrets; it only
recomputes public algorithms from the docs so anyone can check a device offline.

It holds the published computations and readers, and nothing else (tasks/todo.md, M2 group 1): the
embedded BIP39 English list, BIP39 and PBKDF2, C and E, the seal derivation
(docs/seal-watchonly-braille.md, "Seal derivation spec", "The seal image", "Go-ahead code"), the
SeedBook braille and insert positions, the watch-only export (secp256k1, BIP32, descriptors and the
single-part UR code), Ed25519 verification, the bucket tree and the .kcr and KCP1 verifiers, the
encrypted backup's age reader and plaintext v1 parser, and the embedded known answers that every
command runs first (M2 group 3). It opens no file and runs no other program.
The verifier's own recomputation of a device's C, E and words, and braille, arrive in M2.

tools/verify/vectorgen.py, which never ships, loads this file by path. It holds the vector
generators, the backup writer, the label-key signer and the self-test, which checks this file
against vectors/ and, in check 12, checks that a copy of it runs alone.

Usage (Python 3.9+, isolated mode only):
  python3 -I verify.py selftest     run the embedded known answers: one line per group, then exit 0,
                                    or exit 1 naming each failing group
Anything else prints the usage and exits 2 (M2 group 7 adds the mixed and dice commands). The
repo's self-test is
  python3 -I tools/verify/vectorgen.py --selftest
"""

import sys

# Startup guards (tasks/todo.md, M2 group 3), before any other import, when this file runs as a
# script: Python 3.9 or later; isolated mode (-I), so a module planted beside the file (a hashlib.py,
# say) is never imported; and stdout in UTF-8, so braille prints the same in every locale.
if __name__ == "__main__":
    if sys.version_info < (3, 9):
        sys.stderr.write("verify.py needs Python 3.9 or later\n")
        sys.exit(2)
    if not sys.flags.isolated:
        sys.stderr.write("verify.py runs only in isolated mode: python3 -I verify.py ...\n")
        sys.exit(2)
    sys.stdout.reconfigure(encoding="utf-8")

import base64
import binascii
import datetime
import hashlib
import hmac
import re
import struct
import unicodedata

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
OKABE_ITO = ("#000000", "#E69F00", "#56B4E9", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7")

TAG_SEAL = b"KCE/v1/seal"
TAG_SEAL_TAG = b"KCE/v1/seal-tag"
TAG_GO = b"KCE/v1/go"

# Check 6 and vectors/keepcrypt.json: C, E and the dice quota (tasks/todo.md, M1 group 3; CLAUDE.md
# "Domain constants"). vectorgen.py holds the pool and health-test model.
TAG_COMMIT = b"KCE/v1/commit"
TAG_SEED = b"KCE/v1/seed"
DICE = (
    ("min_rolls_12_words", 50),
    ("min_rolls_24_words", 99),
    ("min_rolls_after_collision", 99),
    ("max_rolls", 256),
    ("millibits_per_roll", 2585),
)

# Check 8 and vectors/braille.json: the SeedBook braille format (docs/seal-watchonly-braille.md
# "Braille backup"; CLAUDE.md "Braille (SeedBook)"; tasks/todo.md, M1 group 5, Q6f and Q9). Unified
# English Braille grade 1, one cell per letter, no contractions. Dots are numbered as printed: 1-2-3
# down the left column, 4-5-6 down the right. Core's braille module checks its tables against
# braille.json.
BRAILLE_LETTER_DOTS = (
    ("a", "1"), ("b", "12"), ("c", "14"), ("d", "145"), ("e", "15"), ("f", "124"), ("g", "1245"),
    ("h", "125"), ("i", "24"), ("j", "245"), ("k", "13"), ("l", "123"), ("m", "134"), ("n", "1345"),
    ("o", "135"), ("p", "1234"), ("q", "12345"), ("r", "1235"), ("s", "234"), ("t", "2345"),
    ("u", "136"), ("v", "1236"), ("w", "2456"), ("x", "1346"), ("y", "13456"), ("z", "1356"),
)
# The signs of the text rule (Q6f), after the letters in the canonical table: the number sign opens
# a run of digits, the grade 1 indicator goes before a letter a-j that follows a digit, the hyphen,
# and the blank cell (U+2800) that a space becomes.
BRAILLE_SIGN_DOTS = (("number_sign", "3456"), ("grade1_indicator", "56"), ("hyphen", "36"), ("space", ""))
# Inside a run of digits, digit d is written with the cell of BRAILLE_DIGIT_LETTERS[d]: 1-9 = a-i, 0 = j.
BRAILLE_DIGIT_LETTERS = "jabcdefghi"
SEEDBOOK_FACES = 5  # faces 1-5 carry the first five letters (face 6 is the engraved sequence number)
SEEDBOOK_LIGHTER_FACE = 5  # the fifth letter is a redundancy check, drawn lighter
SEEDBOOK_INSERTS = 12  # inserts per device: one KeepCrypt Hinge or Screw

# BCR-2020-012, "Word List": the 256 Bytewords, byte 0x00 first (copyright 2020 Blockchain Commons,
# BSD-2-Clause-Patent; see vectors/SOURCES.md). The minimal encoding of a byte is its word's first and
# last letters.
BYTEWORDS = tuple(
    """
able acid also apex aqua arch atom aunt
away axis back bald barn belt beta bias
blue body brag brew bulb buzz calm cash
cats chef city claw code cola cook cost
crux curl cusp cyan dark data days deli
dice diet door down draw drop drum dull
duty each easy echo edge epic even exam
exit eyes fact fair fern figs film fish
fizz flap flew flux foxy free frog fuel
fund gala game gear gems gift girl glow
good gray grim guru gush gyro half hang
hard hawk heat help high hill holy hope
horn huts iced idea idle inch inky into
iris iron item jade jazz join jolt jowl
judo jugs jump junk jury keep keno kept
keys kick kiln king kite kiwi knob lamb
lava lazy leaf legs liar limp lion list
logo loud love luau luck lung main many
math maze memo menu meow mild mint miss
monk nail navy need news next noon note
numb obey oboe omit onyx open oval owls
paid part peck play plus poem pool pose
puff puma purr quad quiz race ramp real
redo rich road rock roof ruby ruin runs
rust safe saga scar sets silk skew slot
soap solo song stub surf swan taco task
taxi tent tied time tiny toil tomb toys
trip tuna twin ugly undo unit urge user
vast very veto vial vibe view visa void
vows wall wand warm wasp wave waxy webs
what when whiz wolf work yank yawn yell
yoga yurt zaps zero zest zinc zone zoom
"""
    .split()
)
UR_MAX_CHARS = 4296  # the largest QR alphanumeric capacity (version 40-L); Q6c

# Check 10 and vectors/kcr.json: the signed registry snapshot (.kcr), the signed bucket proof (KCP1)
# behind the go-ahead QR, and the Ed25519 signature over both (docs/seal-watchonly-braille.md "Snapshot
# format", "Go-ahead QR", "Go-ahead code"; CLAUDE.md "Bucket proof", "Check nonce", "Go-ahead code";
# tasks/todo.md, M1 group 7, Q3, Q6b, Q6c). Core's seal module verifies the same bytes with
# ed25519-dalek's verify_strict and checks its results against kcr.json. M9's re-check of a seal
# against a snapshot will use this code (tasks/todo.md, M2 Q22); no M2 command calls it.
TAG_BUCKET = b"KCE/v1/bucket"
BUCKET_BITS = 20  # the lookup prefix: 2^20 buckets
KCR_MAGIC = b"KCR1"
KCP_MAGIC = b"KCP1"
KCR_VERSION = 1
KCR_HEADER_BYTES = 58  # magic 4, version 2, number 8, date 4, count 8, root 32
KCR_SIGNED_BYTES = KCR_HEADER_BYTES + 64  # the header and its signature: 122
KCR_ENTRY_BYTES = 18  # T[0..16] and a u16 registration count
KCR_MAX_ENTRIES = 1 << 22  # the loader's limit (Q6b)
KCP_BASE_BYTES = len(KCP_MAGIC) + KCR_SIGNED_BYTES + 3 + 2 + 32 * BUCKET_BITS  # 771, before the k entries
KCP_UR_TYPE = "keepcrypt-proof"
FRESH_DAYS = 30  # a snapshot or proof is Stale from day 31 (docs "Freshness"; Q5)

# Check 11 and vectors/backup.json: the encrypted backup (docs/build-plan.md "Encrypted backup format";
# docs/seal-watchonly-braille.md "Inside the encrypted backup"; the C2SP age v1 spec, vectors/SOURCES.md
# "Spec values"; tasks/todo.md, M1 group 8, Q1, Q5, Q6e). An age v1 file with one scrypt stanza, armored,
# holding the plaintext v1 below, under a generated 8-word passphrase. Core's backup module reads and
# writes the same bytes with the RustCrypto scrypt, chacha20poly1305, hkdf, hmac and base64ct crates;
# this file reads them with the standard library (hashlib.scrypt where Python has it, cross-checked
# against the pure-Python scrypt here), and vectorgen.py's writer rebuilds the CCTV files byte for byte.
AGE_VERSION_LINE = b"age-encryption.org/v1\n"
AGE_SCRYPT_LABEL = b"age-encryption.org/v1/scrypt"
AGE_HEADER_INFO = b"header"
AGE_PAYLOAD_INFO = b"payload"
AGE_ARMOR_BEGIN = b"-----BEGIN AGE ENCRYPTED FILE-----"
AGE_ARMOR_END = b"-----END AGE ENCRYPTED FILE-----"
AGE_COLUMNS = 64  # armor lines and stanza body lines
AGE_SCRYPT_R = 8
AGE_SCRYPT_P = 1
AGE_SALT_BYTES = 16
AGE_NONCE_BYTES = 16
BACKUP_MAX_WORK_FACTOR = 18  # the reader accepts 1-18, checked before any scrypt work (Q1 i)
BACKUP_MAX_FILE_BYTES = 8 * 1024  # the reader's file cap, armored or binary, checked first (Q1 i)
BACKUP_MAX_CHUNK_BYTES = 4 * 1024  # one final payload chunk of at most 4 KiB of plaintext (Q1 i)
BACKUP_WHITESPACE = b" \t\r\n"  # the ASCII whitespace the armor may have after END
# Fewer than this many bytes of that whitespace after END: the age CLI's own limit (age 1.1.1 and 1.3.2
# refuse 1,024). None before BEGIN: age 1.1.1 reads a file as armor only when BEGIN is its first byte (1.2
# and later skip up to 1,024 bytes of whitespace), so no armor this reader accepts is one age refuses for
# its whitespace.
BACKUP_ARMOR_WHITESPACE_BYTES = 1024
BACKUP_VERSION_LINE = "keepcrypt-backup/v1"

# The BIP39 English word list, embedded because the M2 verifier ships as one file (docs/build-plan.md
# "Release"); copied from the bip39 3.0.0 crate's English list. Check 6 requires the 2,048 words
# joined by LF, plus a final LF, to hash to BIP39_ENGLISH_SHA256, the published SHA-256
# (docs/seal-watchonly-braille.md "Sources"). Sixteen space-separated words per line, so "random"
# (word 1,422) never stands alone on a line, where the banned-API gate's Python-import pattern
# would read it as an import.
BIP39_ENGLISH = tuple(
    """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid
acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance
advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume
asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball
bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle
bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood
blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb
bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable
cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable
capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog
catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine
come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle
craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop
cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn
day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay
deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk
despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital
dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb
dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator
elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy
energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil
evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint
faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field
figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment
gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass
gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun
gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital
host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband
hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial
inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest
invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel
job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup
key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know
lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law
lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty library license life lift light like limb limit
link lion liquid list little live lizard load loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet
maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin
marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure
meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message
metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning
mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music
must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative
neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee
noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay
old olive olympic omit once one onion online only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over
own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper
parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut
pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet
plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony
pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority prison private prize problem process produce profit program
project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz
quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid
rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle
reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove
render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire
retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room
rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness
safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed seek segment select sell seminar senior sense sentence
series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine
ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar simple since sing siren sister situate six size
skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan
slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social
sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin
spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium
staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme
sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim
swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target
task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that
theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token
tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist
toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree
trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try
tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful
useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view
village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave
way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat
wheel when where whip whisper wide width wife wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth
wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo
"""
    .split()
)


# --- Seal derivation -------------------------------------------------------------------------


def bip39_seed(mnemonic):
    """S = PBKDF2-HMAC-SHA512(UTF-8(NFKD(mnemonic)), b"mnemonic", 2048, 64).

    BIP39 salts with b"mnemonic" + NFKD(passphrase); the seal always uses the empty passphrase
    (CLAUDE.md rule 7), so the salt is exactly the 8 bytes b"mnemonic". NFKD is a no-op for the
    ASCII English word list. The mnemonic is used as given: words joined by single spaces.
    """
    password = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, b"mnemonic", 2048, 64)


def leading_bits(data, bits):
    """The first `bits` bits of `data` as an integer, most significant bit first."""
    if not 0 < bits <= 8 * len(data):
        raise ValueError("bit count out of range")
    return int.from_bytes(data, "big") >> (8 * len(data) - bits)


def crockford_base32(value, chars):
    """`value` as exactly `chars` Crockford base32 digits, most significant first (5 bits each)."""
    if value < 0 or value >> (5 * chars):
        raise ValueError("value does not fit")
    return "".join(CROCKFORD[(value >> (5 * (chars - 1 - i))) & 31] for i in range(chars))


def grouped(code, sizes):
    """Display form: `code` split into groups of `sizes`, joined by '-'."""
    if sum(sizes) != len(code):
        raise ValueError("group sizes do not cover the code")
    parts, start = [], 0
    for size in sizes:
        parts.append(code[start : start + size])
        start += size
    return "-".join(parts)


def seal_code(seed):
    """26 chars: Crockford base32 of the top 130 bits of HMAC-SHA256(key=S, msg=b"KCE/v1/seal").

    S is the 64-byte BIP39 seed. 130 bits = 26 x 5, so there is no padding.
    """
    if len(seed) != 64:
        raise ValueError("S must be 64 bytes")
    mac = hmac.new(seed, TAG_SEAL, hashlib.sha256).digest()
    return crockford_base32(leading_bits(mac, 130), 26)


def seal_tag(code):
    """T = SHA256(b"KCE/v1/seal-tag" || code), 32 bytes.

    `code` is the 26 ASCII chars, uppercase, without the display dashes (15 + 26 = 41 bytes hashed).
    """
    if len(code) != 26 or any(c not in CROCKFORD for c in code):
        raise ValueError("seal code must be 26 uppercase Crockford chars without dashes")
    return hashlib.sha256(TAG_SEAL_TAG + code.encode("ascii")).digest()


def seal_id(tag):
    """8 chars: Crockford base32 of the first 40 bits of T."""
    return crockford_base32(leading_bits(tag, 40), 8)


def lookup_prefix(tag):
    """First 5 lowercase hex chars (20 bits) of T."""
    return tag.hex()[:5]


def seal_grid(tag):
    """8 strings of 8 chars ('#' filled, '.' empty).

    The 32 bits of T[1], T[2], T[3], T[4] (0-based), most significant first, fill columns 0-3
    row by row; column 7-c mirrors column c.
    """
    bits = int.from_bytes(tag[1:5], "big")
    rows = []
    for r in range(8):
        left = "".join("#" if (bits >> (31 - (4 * r + c))) & 1 else "." for c in range(4))
        rows.append(left + left[::-1])
    return rows


def seal_colour(tag):
    """(index, hex): index = T[0] mod 8 into the Okabe-Ito palette."""
    index = tag[0] % 8
    return index, OKABE_ITO[index]


def go_ahead_code(tag, nonce):
    """8 chars: Crockford base32 of the first 40 bits of SHA256(b"KCE/v1/go" || T || n).

    T is the 32 raw tag bytes and n the 8 raw nonce bytes (9 + 32 + 8 = 49 bytes hashed).
    """
    if len(tag) != 32 or len(nonce) != 8:
        raise ValueError("T must be 32 bytes and n 8 bytes")
    return crockford_base32(leading_bits(hashlib.sha256(TAG_GO + tag + nonce).digest(), 40), 8)


# --- Seed and words (vectors/keepcrypt.json) -------------------------------------------------


def bip39_words(entropy):
    """BIP39 English words for 16, 20, 24, 28 or 32 bytes of entropy: the bits, then the first
    ENT/32 bits of SHA256(entropy) as checksum, cut into 11-bit indices, most significant first."""
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("BIP39 entropy must be 16 to 32 bytes, a multiple of 4")
    checksum_bits = len(entropy) // 4
    value = (int.from_bytes(entropy, "big") << checksum_bits) | (
        hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits))
    count = (8 * len(entropy) + checksum_bits) // 11
    return [BIP39_ENGLISH[(value >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count)]


def commitment(d):
    """C = SHA256(b"KCE/v1/commit" || D)."""
    return hashlib.sha256(TAG_COMMIT + d).digest()


def mixed_entropy(d, rolls):
    """E = SHA256(b"KCE/v1/seed" || D || len(R) as u64 BE || R), R = the ASCII rolls."""
    r = rolls.encode("ascii")
    return hashlib.sha256(TAG_SEED + d + len(r).to_bytes(8, "big") + r).digest()


def dice_only_entropy(rolls):
    """E = SHA256(R), the same as Coldcard's rolls.py."""
    return hashlib.sha256(rolls.encode("ascii")).digest()


# --- Braille (vectors/braille.json) -----------------------------------------------------------


def braille_cell(dots):
    """The Unicode braille pattern with `dots` raised (a string of digits 1-6): U+2800 + sum 2^(d-1)."""
    return chr(0x2800 + sum(1 << (int(d) - 1) for d in dots))


def mirrored_dots(dots):
    """A cell's left-right mirror image: dots 1 and 4, 2 and 5, 3 and 6 swap; digits ascending."""
    return "".join(sorted(str((int(d) + 2) % 6 + 1) for d in dots))


def braille_mirror_pairs():
    """Every pair of distinct letters whose cells mirror each other, computed from the dots."""
    letter_of = {dots: letter for letter, dots in BRAILLE_LETTER_DOTS}
    return [(letter, letter_of[mirrored_dots(dots)]) for letter, dots in BRAILLE_LETTER_DOTS
            if letter_of.get(mirrored_dots(dots), letter) > letter]


def braille_mirror_partner():
    """{letter: its mirror partner} for the letters of the mirror pairs."""
    partner = {}
    for a, b in braille_mirror_pairs():
        partner[a], partner[b] = b, a
    return partner


def braille_text(text):
    """UEB grade 1 cells for `text` (Q6f): a-z, 0-9, space and hyphen, anything else a ValueError.

    A digit outside a run of digits opens one with the number sign; a letter a-j right after a digit
    takes the grade 1 indicator first, so it is not read as a digit; any letter, a space (the blank
    cell) or a hyphen ends the run.
    """
    letter_dots = dict(BRAILLE_LETTER_DOTS)
    sign = {name: braille_cell(dots) for name, dots in BRAILLE_SIGN_DOTS}
    out, in_digits = [], False
    for ch in text:
        if "0" <= ch <= "9":
            if not in_digits:
                out.append(sign["number_sign"])
                in_digits = True
            out.append(braille_cell(letter_dots[BRAILLE_DIGIT_LETTERS[int(ch)]]))
        elif "a" <= ch <= "z":
            if in_digits and ch <= "j":
                out.append(sign["grade1_indicator"])
            in_digits = False
            out.append(braille_cell(letter_dots[ch]))
        elif ch in (" ", "-"):
            in_digits = False
            out.append(sign["space" if ch == " " else "hyphen"])
        else:
            raise ValueError("braille text takes a-z, 0-9, space and hyphen only")
    return "".join(out)


def braille_table_text():
    """The canonical cell table, the bytes core's Braille KAT hashes: for a-z, then the signs, one
    line 'name cell dots' ended by LF, with dots "0" for the blank cell."""
    rows = BRAILLE_LETTER_DOTS + BRAILLE_SIGN_DOTS
    return "".join("%s %s %s\n" % (name, braille_cell(dots), dots or "0") for name, dots in rows)


def seedbook_faces(word):
    """Faces 1-5 of an insert: the first five letters, None for each blank face."""
    return [word[i] if i < len(word) else None for i in range(SEEDBOOK_FACES)]


def insert_positions(word_count):
    """Each word position of a 12- or 24-word seed with its device, the device count and the engraved
    sequence number 01-12 (Q9: both insert sets are engraved 01-12)."""
    devices = word_count // SEEDBOOK_INSERTS
    return [{"position": p, "device": (p - 1) // SEEDBOOK_INSERTS + 1, "devices": devices,
             "sequence": (p - 1) % SEEDBOOK_INSERTS + 1} for p in range(1, word_count + 1)]


def backup_braille_lines(words):
    """The plaintext backup's braille: lines (Q6e): '  NN ' then every letter's cell."""
    return ["  %02d %s" % (p, braille_text(word)) for p, word in enumerate(words, 1)]


# --- Watch-only export and single-part UR (vectors/watchonly.json) -----------------------------
# Standard library only: secp256k1 arithmetic, RIPEMD-160, BIP32, bech32, the BIP-380 checksum, a
# dCBOR writer, Bytewords and CRC-32, run on public test mnemonics only. Nothing here is constant
# time; it never sees a real secret.

SECP256K1_P = 2 ** 256 - 2 ** 32 - 977
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
XPUB_VERSION = bytes.fromhex("0488b21e")
HARDENED = 0x80000000
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# BIP-380 "Checksum", the reference code's character sets and generator.
DESCRIPTOR_INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
DESCRIPTOR_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
DESCRIPTOR_GENERATOR = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)


def ec_add(a, b):
    """Affine point addition on secp256k1; None is the point at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SECP256K1_P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], SECP256K1_P - 2, SECP256K1_P)
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], SECP256K1_P - 2, SECP256K1_P)
    slope %= SECP256K1_P
    x = (slope * slope - a[0] - b[0]) % SECP256K1_P
    return x, (slope * (a[0] - x) - a[1]) % SECP256K1_P


def ec_public(k):
    """k * G by double-and-add, as a 33-byte compressed public key."""
    point, addend = None, SECP256K1_G
    while k:
        if k & 1:
            point = ec_add(point, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def ripemd160_pure(data):
    """RIPEMD-160 (Dobbertin, Bosselaers and Preneel), in pure Python for interpreters whose hashlib
    lacks it; check 9 compares it with hashlib's where hashlib has one."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    left_words = (
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13)
    right_words = (
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11)
    left_shifts = (
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6)
    right_shifts = (
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11)
    left_k = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    right_k = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "little")
    for offset in range(0, len(padded), 64):
        x = [int.from_bytes(padded[offset + 4 * i: offset + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = rol((al + f(j, bl, cl, dl) + x[left_words[j]] + left_k[j // 16]) & 0xFFFFFFFF, left_shifts[j]) + el
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t & 0xFFFFFFFF
            t = rol((ar + f(79 - j, br, cr, dr) + x[right_words[j]] + right_k[j // 16]) & 0xFFFFFFFF,
                    right_shifts[j]) + er
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t & 0xFFFFFFFF
        h = [(h[1] + cl + dr) & 0xFFFFFFFF, (h[2] + dl + er) & 0xFFFFFFFF, (h[3] + el + ar) & 0xFFFFFFFF,
             (h[4] + al + br) & 0xFFFFFFFF, (h[0] + bl + cr) & 0xFFFFFFFF]
    return b"".join(v.to_bytes(4, "little") for v in h)


def hash160(data):
    """RIPEMD-160(SHA-256(data)), with the pure-Python RIPEMD-160 (cross-checked by check 9)."""
    return ripemd160_pure(hashlib.sha256(data).digest())


def base58check(payload):
    """Base58 of payload || first 4 bytes of SHA-256(SHA-256(payload))."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value, text = int.from_bytes(data, "big"), ""
    while value:
        value, digit = divmod(value, 58)
        text = BASE58[digit] + text
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + text


def bip39_seed_with_passphrase(mnemonic, passphrase, normalize=True):
    """BIP39 S = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" + NFKD(passphrase), 2048, 64). With
    normalize=False the passphrase goes in as typed, the bug core must never have."""
    salt = "mnemonic" + (unicodedata.normalize("NFKD", passphrase) if normalize else passphrase)
    password = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt.encode("utf-8"), 2048, 64)


def bip32_master(seed):
    """(private key, chain code) of the BIP32 master key."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(digest[:32], "big"), digest[32:]


def bip32_child(key, chain, index):
    """CKDpriv: (private key, chain code) of child `index` (hardened at 2^31 and above)."""
    if index >= HARDENED:
        data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = ec_public(key) + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (tweak + key) % SECP256K1_N
    if tweak >= SECP256K1_N or child == 0:
        raise ValueError("invalid BIP32 child (probability below 2^-127)")
    return child, digest[32:]


def bip32_fingerprint(key):
    """The first 4 bytes of HASH160 of the compressed public key."""
    return hash160(ec_public(key))[:4]


def bip32_derive(seed, path):
    """[(index, key, chain code)] for every step of `path` from the master, master first (index None)."""
    key, chain = bip32_master(seed)
    steps = [(None, key, chain)]
    for index in path:
        key, chain = bip32_child(key, chain, index)
        steps.append((index, key, chain))
    return steps


def serialize_xpub(version, depth, parent_fingerprint, index, chain, public_key):
    """A BIP32 extended public key: version || depth || parent fingerprint || child number || chain code
    || compressed key, in Base58Check."""
    return base58check(version + bytes([depth]) + parent_fingerprint + index.to_bytes(4, "big") + chain + public_key)


def bech32_polymod(values):
    """BIP-173's checksum function."""
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def p2wpkh_address(public_key):
    """The mainnet P2WPKH address (BIP-173, witness version 0) of a compressed public key."""
    program, acc, bits, data = hash160(public_key), 0, 0, [0]
    for byte in program:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    polymod = bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return "bc1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def descriptor_polymod(symbols):
    """BIP-380's checksum polynomial over GF(32)."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= DESCRIPTOR_GENERATOR[i]
    return chk


def descriptor_symbols(text):
    """BIP-380's expansion of a descriptor into checksum symbols, or None for a character outside
    the input character set."""
    groups, symbols = [], []
    for ch in text:
        position = DESCRIPTOR_INPUT_CHARSET.find(ch)
        if position < 0:
            return None
        symbols.append(position & 31)
        groups.append(position >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descriptor_checksum(text):
    """The 8-character BIP-380 checksum of a descriptor."""
    symbols = descriptor_symbols(text)
    if symbols is None:
        raise ValueError("a descriptor character outside the BIP-380 input set")
    value = descriptor_polymod(symbols + [0] * 8) ^ 1
    return "".join(DESCRIPTOR_CHECKSUM_CHARSET[(value >> (5 * (7 - i))) & 31] for i in range(8))


def descriptor_checksum_valid(text):
    """True for a descriptor that ends in '#' and its valid 8-character checksum."""
    if len(text) < 9 or text[-9] != "#" or any(c not in DESCRIPTOR_CHECKSUM_CHARSET for c in text[-8:]):
        return False
    symbols = descriptor_symbols(text[:-9])
    if symbols is None:
        return False
    return descriptor_polymod(symbols + [DESCRIPTOR_CHECKSUM_CHARSET.find(c) for c in text[-8:]]) == 1


def cbor_head(major, value):
    """A CBOR head in its shortest form: major type (0-7) and its argument."""
    if value < 24:
        return bytes([major << 5 | value])
    for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (8 * size):
            return bytes([major << 5 | extra]) + value.to_bytes(size, "big")
    raise ValueError("a CBOR argument above 2^64 - 1")


def cbor_encode(item):
    """Deterministic CBOR of an item (WATCHONLY_SPEC "cbor"): shortest heads, definite lengths, map keys
    unique and sorted by their encoded bytes."""
    kind = item[0]
    if kind == "uint":
        return cbor_head(0, item[1])
    if kind == "bytes":
        data = bytes.fromhex(item[1])
        return cbor_head(2, len(data)) + data
    if kind == "array":
        return cbor_head(4, len(item[1])) + b"".join(cbor_encode(i) for i in item[1])
    if kind == "map":
        pairs = sorted((cbor_encode(k), cbor_encode(v)) for k, v in item[1])
        if len(set(k for k, _ in pairs)) != len(pairs):
            raise ValueError("duplicate CBOR map key")
        return cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    if kind == "bool":
        return b"\xf5" if item[1] else b"\xf4"
    if kind == "tag":
        return cbor_head(6, item[1]) + cbor_encode(item[2])
    raise ValueError("unknown CBOR item kind %r" % kind)


def crc32_table():
    """The 256-entry table of CRC-32/ISO-HDLC (reflected polynomial 0xedb88320)."""
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    return table


def crc32(data):
    """CRC-32/ISO-HDLC, table-driven (check 9 compares it with zlib's)."""
    table, c = crc32_table(), 0xFFFFFFFF
    for byte in data:
        c = table[(c ^ byte) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def bytewords_minimal(data):
    """Minimal Bytewords: each byte as its word's first and last letters."""
    return "".join(BYTEWORDS[b][0] + BYTEWORDS[b][3] for b in data)


def ur_single(ur_type, cbor):
    """A single-part UR: ur:<type>/<minimal Bytewords of CBOR || CRC-32 big-endian>."""
    return "ur:%s/%s" % (ur_type, bytewords_minimal(cbor + crc32(cbor).to_bytes(4, "big")))


def ur_decode_single(expected_type, text):
    """The strict single-part reader, rebuilt apart from core (WATCHONLY_SPEC "ur_decoder"): (the CBOR
    byte string's bytes, None), or (None, the name of the first rule the text breaks). Like core, it reads
    the UTF-8 bytes of the text: the limit and the even length count bytes, and a byte of a non-ASCII
    character (0x80 or above) is no letter, so it matches no rule."""
    raw = text.encode("utf-8")
    if len(raw) > UR_MAX_CHARS:
        return None, "TooLong"
    has_upper, has_lower = any(0x41 <= b <= 0x5A for b in raw), any(0x61 <= b <= 0x7A for b in raw)
    if has_upper and has_lower:
        return None, "MixedCase"
    raw = bytes(b + 32 if 0x41 <= b <= 0x5A else b for b in raw)
    if not raw.startswith(b"ur:") or b"/" not in raw[3:]:
        return None, "NotUr"
    ur_type, message = raw[3:].split(b"/", 1)
    if ur_type != expected_type.encode("ascii"):
        return None, "WrongType"
    if b"/" in message:
        return None, "MultiPart"
    if len(message) % 2:
        return None, "OddLength"
    byte_of = {(word[0] + word[3]).encode("ascii"): n for n, word in enumerate(BYTEWORDS)}
    pairs = [message[i:i + 2] for i in range(0, len(message), 2)]
    if any(pair not in byte_of for pair in pairs):
        return None, "UnknownByteword"
    data = bytes(byte_of[pair] for pair in pairs)
    if len(data) < 4 or crc32(data[:-4]).to_bytes(4, "big") != data[-4:]:
        return None, "BadChecksum"
    cbor = data[:-4]
    if not cbor or cbor[0] >> 5 != 2:
        return None, "NotByteString"
    info = cbor[0] & 31
    if info == 31:
        return None, "IndefiniteLength"
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info, 0) if info < 28 else None
    if size is None or len(cbor) < 1 + size:
        return None, "NotByteString"
    length = int.from_bytes(cbor[1:1 + size], "big") if size else info
    if cbor_head(2, length) != cbor[:1 + size]:
        return None, "NonShortestHead"
    if len(cbor) < 1 + size + length:
        return None, "NotByteString"
    if len(cbor) > 1 + size + length:
        return None, "TrailingBytes"
    return cbor[1 + size:], None


def cbor_byte_string(data):
    """A CBOR byte string item for raw bytes."""
    return ("bytes", data.hex())


def hdkey_item(public_key, chain, components, source_fingerprint, parent_fingerprint):
    """A v1 crypto-hdkey (tag 303) with its crypto-keypath origin (tag 304); a zero fingerprint is
    omitted (BCR-2020-007: uint32 .ne 0)."""
    path = ("array", tuple(c for index, hardened in components for c in (("uint", index), ("bool", hardened))))
    keypath = [(("uint", 1), path)]
    if source_fingerprint:
        keypath.append((("uint", 2), ("uint", source_fingerprint)))
    fields = [(("uint", 3), cbor_byte_string(public_key)), (("uint", 4), cbor_byte_string(chain)),
              (("uint", 6), ("tag", 304, ("map", tuple(keypath))))]
    if parent_fingerprint:
        fields.append((("uint", 8), ("uint", parent_fingerprint)))
    return ("tag", 303, ("map", tuple(fields)))


def crypto_account_item(master_fingerprint, outputs):
    """A v1 crypto-account, untagged: {1: master fingerprint, 2: [outputs]}; each output is (script tags,
    hdkey item), the tags outermost first."""
    wrapped = []
    for tags, hdkey in outputs:
        item = hdkey
        for tag in reversed(tags):
            item = ("tag", tag, item)
        wrapped.append(item)
    return ("map", ((("uint", 1), ("uint", master_fingerprint)), (("uint", 2), ("array", tuple(wrapped)))))


def watch_only_wallet(name, mnemonic, passphrase):
    """One watchonly.json wallet: the BIP84 account export for a mnemonic and optional passphrase."""
    seed = bip39_seed_with_passphrase(mnemonic, passphrase or "")
    account_path = (84 + HARDENED, HARDENED, HARDENED)
    steps = bip32_derive(seed, account_path)
    master_fp = bip32_fingerprint(steps[0][1])
    parent_fp = bip32_fingerprint(steps[2][1])
    _, account_key, account_chain = steps[3]
    account_public = ec_public(account_key)
    xpub = serialize_xpub(XPUB_VERSION, 3, parent_fp, HARDENED, account_chain, account_public)

    def address(change):
        key, chain = bip32_child(account_key, account_chain, change)
        return p2wpkh_address(ec_public(bip32_child(key, chain, 0)[0]))

    origin = "[%s/84h/0h/0h]" % master_fp.hex()
    receive, change = "wpkh(%s%s/0/*)" % (origin, xpub), "wpkh(%s%s/1/*)" % (origin, xpub)
    apostrophe = "wpkh([%s/84'/0'/0']%s/0/*)" % (master_fp.hex(), xpub)
    hdkey = hdkey_item(account_public, account_chain, ((84, True), (0, True), (0, True)),
                       int.from_bytes(master_fp, "big"), int.from_bytes(parent_fp, "big"))
    cbor = cbor_encode(crypto_account_item(int.from_bytes(master_fp, "big"), [((308, 404), hdkey)]))
    ur = ur_single("crypto-account", cbor)
    wallet = {
        "name": name,
        "mnemonic": mnemonic,
        "passphrase": passphrase,
        "fingerprint": master_fp.hex(),
        "account_xpub": xpub,
        "account_key_hex": account_public.hex(),
        "account_chain_code_hex": account_chain.hex(),
        "account_parent_fingerprint": parent_fp.hex(),
        "receive_descriptor": receive + "#" + descriptor_checksum(receive),
        "change_descriptor": change + "#" + descriptor_checksum(change),
        "receive_descriptor_apostrophe": apostrophe + "#" + descriptor_checksum(apostrophe),
        "first_receive_address": address(0),
        "first_change_address": address(1),
        "crypto_account_cbor_hex": cbor.hex(),
        "crypto_account_ur": ur,
        "qr_text": ur.upper(),
    }
    if passphrase is not None and unicodedata.normalize("NFKD", passphrase) != passphrase:
        unnormalized = bip39_seed_with_passphrase(mnemonic, passphrase, normalize=False)
        wallet["unnormalized_fingerprint"] = bip32_fingerprint(bip32_master(unnormalized)[0]).hex()
    return wallet


# --- Ed25519, the bucket tree, .kcr snapshots and KCP1 proofs (vectors/kcr.json) ---------------
# Standard library only. Ed25519 follows RFC 8032 section 5.1 on the twisted Edwards curve
# -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19), in extended coordinates (X, Y, Z, T) with x = X/Z,
# y = Y/Z and xy = T/Z. Nothing here is constant time: it only verifies public data.

ED25519_P = 2 ** 255 - 19
ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493
ED25519_D = -121665 * pow(121666, ED25519_P - 2, ED25519_P) % ED25519_P
ED25519_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_IDENTITY = (0, 1, 1, 0)


def ed_add(a, b):
    """The sum of two points (the complete addition law for a = -1; it also doubles)."""
    p = ED25519_P
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e1 = (y1 - x1) * (y2 - x2) % p
    e2 = (y1 + x1) * (y2 + x2) % p
    e3 = 2 * ED25519_D * t1 * t2 % p
    e4 = 2 * z1 * z2 % p
    e, f, g, h = e2 - e1, e4 - e3, e4 + e3, e2 + e1
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def ed_negate(point):
    """-P = (-x, y)."""
    x, y, z, t = point
    return (-x % ED25519_P, y, z, -t % ED25519_P)


def ed_multiply(scalar, point):
    """[scalar]P, double and add from the top bit."""
    result = ED25519_IDENTITY
    for bit in range(scalar.bit_length() - 1, -1, -1):
        result = ed_add(result, result)
        if scalar >> bit & 1:
            result = ed_add(result, point)
    return result


def ed_encode(point):
    """32 bytes: y little-endian, with the low bit of x in the top bit."""
    x, y, z, _ = point
    z_inverse = pow(z, ED25519_P - 2, ED25519_P)
    x, y = x * z_inverse % ED25519_P, y * z_inverse % ED25519_P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def ed_decode(data):
    """The point 32 bytes encode (RFC 8032 section 5.1.3), or None: y must be below p, x^2 must have a
    square root, and x = 0 must come with a clear sign bit."""
    p = ED25519_P
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(ED25519_D * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * ED25519_SQRT_M1 % p
    if (x * x - x2) % p:
        return None
    if x & 1 != sign:
        x = p - x
    return (x, y, 1, x * y % p)


# The base point: y = 4/5, x even.
ED25519_BASE = ed_decode((4 * pow(5, ED25519_P - 2, ED25519_P) % ED25519_P).to_bytes(32, "little"))


def ed_small_order(point):
    """True if [8]P is the identity."""
    return ed_encode(ed_multiply(8, point)) == ed_encode(ED25519_IDENTITY)


def ed25519_verify(public_key, message, signature):
    """verify_strict (KCR_SPEC "ed25519"): True only if the key and R decode, S is below L, neither the
    key nor R is of small order, and [S]B - [k]A encodes to R's bytes."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point, r_point = ed_decode(public_key), ed_decode(signature[:32])
    if a_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_L or ed_small_order(a_point) or ed_small_order(r_point):
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % ED25519_L
    check = ed_add(ed_multiply(s, ED25519_BASE), ed_negate(ed_multiply(k, a_point)))
    return ed_encode(check) == signature[:32]


def merkle_leaf(index, entries):
    """leaf(i) = SHA-256(0x00 || "KCE/v1/bucket" || i as 3 bytes, big-endian || the bucket's entries)."""
    return hashlib.sha256(b"\x00" + TAG_BUCKET + index.to_bytes(3, "big") + entries).digest()


def merkle_node(left, right):
    """node = SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


_EMPTY_TREE = []


def merkle_empty_levels():
    """The hash of every empty subtree, precomputed once per run: levels[j] holds the 2^(20 - j) nodes of
    level j, 32 bytes each, joined (level 0 the empty leaves, level 20 the empty root). Every leaf
    hashes its own index, so empty subtrees differ by position and all 2^21 - 1 hashes are kept."""
    if _EMPTY_TREE:
        return _EMPTY_TREE
    sha256, head = hashlib.sha256, b"\x00" + TAG_BUCKET
    level = bytearray()
    for index in range(1 << BUCKET_BITS):
        level += sha256(head + index.to_bytes(3, "big")).digest()
    levels = [bytes(level)]
    for _ in range(BUCKET_BITS):
        below, level = levels[-1], bytearray()
        for start in range(0, len(below), 64):
            level += sha256(b"\x01" + below[start:start + 64]).digest()
        levels.append(bytes(level))
    _EMPTY_TREE.extend(levels)
    return _EMPTY_TREE


def merkle_tree(buckets):
    """The bucket tree where `buckets` maps each non-empty bucket index to its entries' bytes: per level,
    a dict of the nodes that differ from the empty tree. Only the paths above those buckets are hashed."""
    level = {index: merkle_leaf(index, entries) for index, entries in buckets.items() if entries}
    tree = [level]
    for j in range(BUCKET_BITS):
        level = {position: merkle_node(merkle_at(tree, j, 2 * position), merkle_at(tree, j, 2 * position + 1))
                 for position in sorted(set(index >> 1 for index in level))}
        tree.append(level)
    return tree


def merkle_at(tree, level, position):
    """The node at (level, position): from the tree where a bucket below it is filled, else empty."""
    node = tree[level].get(position)
    if node is not None:
        return node
    return merkle_empty_levels()[level][32 * position:32 * position + 32]


def merkle_root(tree):
    return merkle_at(tree, BUCKET_BITS, 0)


def merkle_path_root(index, entries, siblings):
    """The root a leaf and its path give: at level j the node is on the right when (index >> j) & 1."""
    node = merkle_leaf(index, entries)
    for j in range(BUCKET_BITS):
        sibling = siblings[32 * j:32 * j + 32]
        node = merkle_node(sibling, node) if index >> j & 1 else merkle_node(node, sibling)
    return node


def kcr_bucket_of(tag):
    """The bucket: the first 20 bits of T (or of T[0..16])."""
    return int.from_bytes(tag[:3], "big") >> 4


def kcr_buckets(body):
    """The entries of a body grouped by bucket, in body order: {index: bytes}."""
    buckets = {}
    for start in range(0, len(body), KCR_ENTRY_BYTES):
        entry = body[start:start + KCR_ENTRY_BYTES]
        index = kcr_bucket_of(entry)
        buckets[index] = buckets.get(index, b"") + entry
    return buckets


def kcr_date(value):
    """A header date (YYYYMMDD) as a datetime.date, or None if it is not a real Gregorian date in years
    1-9999."""
    try:
        return datetime.date(value // 10000, value // 100 % 100, value % 100)
    except ValueError:
        return None


def kcr_freshness(date, today):
    """Current up to 30 days old, Stale from day 31, Future when after today."""
    age = kcr_date(today).toordinal() - kcr_date(date).toordinal()
    if age < 0:
        return "Future"
    return "Current" if age <= FRESH_DAYS else "Stale"


def kcr_read_header(signed, key):
    """The header checks shared by snapshots and proofs, in order: (fields, None) or (None, error)."""
    header, signature = signed[:KCR_HEADER_BYTES], signed[KCR_HEADER_BYTES:KCR_SIGNED_BYTES]
    if header[:4] != KCR_MAGIC:
        return None, "BadMagic"
    if int.from_bytes(header[4:6], "big") != KCR_VERSION:
        return None, "BadVersion"
    if not ed25519_verify(key, header, signature):
        return None, "BadSignature"
    fields = {"number": int.from_bytes(header[6:14], "big"), "date": int.from_bytes(header[14:18], "big"),
              "count": int.from_bytes(header[18:26], "big"), "root": header[26:58]}
    if kcr_date(fields["date"]) is None:
        return None, "BadDate"
    if fields["count"] > KCR_MAX_ENTRIES:
        return None, "TooManyEntries"
    return fields, None


def kcr_entries_error(entries, bucket=None):
    """The first entry rule broken, in entry order (KCR_SPEC "snapshot_checks", "proof_checks"), or None."""
    previous = None
    for start in range(0, len(entries), KCR_ENTRY_BYTES):
        tag, count = entries[start:start + 16], int.from_bytes(entries[start + 16:start + 18], "big")
        if bucket is not None and kcr_bucket_of(tag) != bucket:
            return "EntryOutsideBucket"
        if previous is not None and tag == previous:
            return "Duplicate"
        if previous is not None and tag < previous:
            return "Unsorted"
        if count == 0:
            return "ZeroCount"
        previous = tag
    return None


def kcr_verify(data, key):
    """A snapshot, checked in KCR_SPEC "snapshot_checks" order: (fields with the body, None) or (None,
    error)."""
    if len(data) < KCR_SIGNED_BYTES:
        return None, "TooShort"
    fields, error = kcr_read_header(data[:KCR_SIGNED_BYTES], key)
    if error:
        return None, error
    if len(data) != KCR_SIGNED_BYTES + KCR_ENTRY_BYTES * fields["count"]:
        return None, "BadLength"
    body = data[KCR_SIGNED_BYTES:]
    error = kcr_entries_error(body)
    if error:
        return None, error
    if merkle_root(merkle_tree(kcr_buckets(body))) != fields["root"]:
        return None, "RootMismatch"
    fields["body"] = body
    return fields, None


def kcp1_verify(data, key):
    """A KCP1 proof, checked in KCR_SPEC "proof_checks" order: (fields with the bucket and its entries,
    None) or (None, error)."""
    if len(data) < KCP_BASE_BYTES:
        return None, "TooShort"
    if data[:4] != KCP_MAGIC:
        return None, "BadMagic"
    fields, error = kcr_read_header(data[4:4 + KCR_SIGNED_BYTES], key)
    if error:
        return None, error
    at = 4 + KCR_SIGNED_BYTES
    bucket, k = int.from_bytes(data[at:at + 3], "big"), int.from_bytes(data[at + 3:at + 5], "big")
    if bucket >= 1 << BUCKET_BITS:
        return None, "BucketOutOfRange"
    if len(data) != KCP_BASE_BYTES + KCR_ENTRY_BYTES * k:
        return None, "BadLength"
    if k > fields["count"]:
        return None, "ProofCount"
    entries = data[at + 5:at + 5 + KCR_ENTRY_BYTES * k]
    error = kcr_entries_error(entries, bucket)
    if error:
        return None, error
    if merkle_path_root(bucket, entries, data[at + 5 + KCR_ENTRY_BYTES * k:]) != fields["root"]:
        return None, "RootMismatch"
    fields.update(bucket=bucket, entries=entries)
    return fields, None


def kcp1_verify_ur(text, key):
    """A go-ahead QR text: the strict UR decoder, then kcp1_verify."""
    data, error = ur_decode_single(KCP_UR_TYPE, text)
    if error:
        return None, "Ur(%s)" % error
    return kcp1_verify(data, key)


def kcr_count_of(entries, tag):
    """The registration count of T[0..16] among sorted entries, or None."""
    for start in range(0, len(entries), KCR_ENTRY_BYTES):
        if entries[start:start + 16] == tag[:16]:
            return int.from_bytes(entries[start + 16:start + 18], "big")
    return None


# --- The encrypted backup: age v1 with one scrypt stanza, plaintext v1 (vectors/backup.json)


class BackupRefused(Exception):
    """A refused backup file or plaintext, or a failed draw. `error` names core's error as backup.json
    writes it: Backup(TooLarge), Backup(Armor), Backup(Header), Backup(WorkFactor), Backup(HeaderMac),
    Backup(Payload), Backup(Plaintext), Backup(UnsupportedVersion), WrongPassphrase or
    Source(NoUsableDraw). It is raised as BackupRefused(error), so `error` is the exception's one
    argument (no __init__, since check 12 allows no dunder attribute)."""

    @property
    def error(self):
        return self.args[0]


MASK32 = 0xFFFFFFFF
B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def rotl32(value, bits):
    value &= MASK32
    return ((value << bits) & MASK32) | (value >> (32 - bits))


def chacha20_block(key, counter, nonce):
    """RFC 8439 2.3: one 64-byte ChaCha20 block for a 32-byte key, a 32-bit counter and a 12-byte nonce."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    x = list(state)
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            x[a] = (x[a] + x[b]) & MASK32
            x[d] = rotl32(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & MASK32
            x[b] = rotl32(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & MASK32
            x[d] = rotl32(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & MASK32
            x[b] = rotl32(x[b] ^ x[c], 7)
    return struct.pack("<16I", *((x[i] + state[i]) & MASK32 for i in range(16)))


def chacha20_xor(key, counter, nonce, data):
    """RFC 8439 2.4: data XOR the ChaCha20 keystream from block `counter` on."""
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(p ^ k for p, k in zip(data[i:i + 64], block))
    return bytes(out)


def poly1305(key, message):
    """RFC 8439 2.5: the 16-byte Poly1305 tag of `message` under a 32-byte one-time key."""
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(message), 16):
        acc = (acc + int.from_bytes(message[i:i + 16] + b"\x01", "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def chacha20poly1305_tag(key, nonce, ciphertext, aad):
    """RFC 8439 2.8: the tag over the AAD and the ciphertext, each zero-padded to 16 bytes, then both lengths."""
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    padded = aad + bytes(-len(aad) % 16) + ciphertext + bytes(-len(ciphertext) % 16)
    return poly1305(one_time_key, padded + struct.pack("<QQ", len(aad), len(ciphertext)))


def chacha20poly1305_open(key, nonce, sealed, aad=b""):
    """The plaintext of `sealed` (ciphertext || tag), or None if it is shorter than a tag or the tag is wrong."""
    if len(sealed) < 16:
        return None
    ciphertext, tag = sealed[:-16], sealed[-16:]
    if not hmac.compare_digest(chacha20poly1305_tag(key, nonce, ciphertext, aad), tag):
        return None
    return chacha20_xor(key, 1, nonce, ciphertext)


def hkdf_sha256(ikm, salt, info):
    """RFC 5869 HKDF-SHA256 with 32 bytes of output: extract, then the first expand block."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def salsa20_8(words):
    """The Salsa20/8 core (RFC 7914 3) on 16 32-bit words: 4 double rounds, then the input added."""
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = words
    for _ in range(4):
        x4 ^= rotl32(x0 + x12, 7)
        x8 ^= rotl32(x4 + x0, 9)
        x12 ^= rotl32(x8 + x4, 13)
        x0 ^= rotl32(x12 + x8, 18)
        x9 ^= rotl32(x5 + x1, 7)
        x13 ^= rotl32(x9 + x5, 9)
        x1 ^= rotl32(x13 + x9, 13)
        x5 ^= rotl32(x1 + x13, 18)
        x14 ^= rotl32(x10 + x6, 7)
        x2 ^= rotl32(x14 + x10, 9)
        x6 ^= rotl32(x2 + x14, 13)
        x10 ^= rotl32(x6 + x2, 18)
        x3 ^= rotl32(x15 + x11, 7)
        x7 ^= rotl32(x3 + x15, 9)
        x11 ^= rotl32(x7 + x3, 13)
        x15 ^= rotl32(x11 + x7, 18)
        x1 ^= rotl32(x0 + x3, 7)
        x2 ^= rotl32(x1 + x0, 9)
        x3 ^= rotl32(x2 + x1, 13)
        x0 ^= rotl32(x3 + x2, 18)
        x6 ^= rotl32(x5 + x4, 7)
        x7 ^= rotl32(x6 + x5, 9)
        x4 ^= rotl32(x7 + x6, 13)
        x5 ^= rotl32(x4 + x7, 18)
        x11 ^= rotl32(x10 + x9, 7)
        x8 ^= rotl32(x11 + x10, 9)
        x9 ^= rotl32(x8 + x11, 13)
        x10 ^= rotl32(x9 + x8, 18)
        x12 ^= rotl32(x15 + x14, 7)
        x13 ^= rotl32(x12 + x15, 9)
        x14 ^= rotl32(x13 + x12, 13)
        x15 ^= rotl32(x14 + x13, 18)
    out = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
    return [(o + w) & MASK32 for o, w in zip(out, words)]


def scrypt_block_mix(block, r):
    """RFC 7914 4: BlockMix over 2r 64-byte blocks held as 32r words."""
    x = block[-16:]
    mixed = []
    for i in range(2 * r):
        x = salsa20_8([a ^ b for a, b in zip(x, block[16 * i:16 * i + 16])])
        mixed.append(x)
    return [w for i in range(0, 2 * r, 2) for w in mixed[i]] + [w for i in range(1, 2 * r, 2) for w in mixed[i]]


def scrypt_pure(password, salt, log_n, r, p, length):
    """RFC 7914 scrypt in pure Python, for Pythons whose hashlib has no scrypt (and cross-checked against
    hashlib.scrypt where it has one). Fast enough for work factor 10, never for 18."""
    n = 1 << log_n
    data = hashlib.pbkdf2_hmac("sha256", password, salt, 1, 128 * r * p)
    out = b""
    for i in range(p):
        x = list(struct.unpack("<%dI" % (32 * r), data[128 * r * i:128 * r * (i + 1)]))
        table = []
        for _ in range(n):
            table.append(x)
            x = scrypt_block_mix(x, r)
        for _ in range(n):
            j = x[16 * (2 * r - 1)] & (n - 1)
            x = scrypt_block_mix([a ^ b for a, b in zip(x, table[j])], r)
        out += struct.pack("<%dI" % (32 * r), *x)
    return hashlib.pbkdf2_hmac("sha256", password, out, 1, length)


_AGE_SCRYPT_CACHE = {}
# How many age wrap keys were asked for: check 11 uses it to prove a refused case never reached scrypt.
AGE_SCRYPT_CALLS = [0]


def age_wrap_key(passphrase, salt, log_n):
    """The scrypt stanza's wrap key: scrypt(N = 2^log_n, r = 8, p = 1, dkLen = 32, S = label || salt,
    P = passphrase), by hashlib where it has scrypt, else in pure Python. Cached per run."""
    AGE_SCRYPT_CALLS[0] += 1
    key = (passphrase, salt, log_n)
    if key not in _AGE_SCRYPT_CACHE:
        label_salt = AGE_SCRYPT_LABEL + salt
        if hasattr(hashlib, "scrypt"):
            _AGE_SCRYPT_CACHE[key] = hashlib.scrypt(passphrase, salt=label_salt, n=1 << log_n, r=AGE_SCRYPT_R,
                                                    p=AGE_SCRYPT_P, maxmem=1 << 29, dklen=32)
        else:
            _AGE_SCRYPT_CACHE[key] = scrypt_pure(passphrase, label_salt, log_n, AGE_SCRYPT_R, AGE_SCRYPT_P, 32)
    return _AGE_SCRYPT_CACHE[key]


def b64_unpadded(data):
    """Standard base64 without '=' padding (the age header's encoding)."""
    return base64.b64encode(data).rstrip(b"=")


def b64_decode_unpadded(text, error):
    """Decode canonical unpadded base64, or refuse with `error`: only the 64 alphabet characters, and the
    bytes must encode back to exactly `text` (so no padding and no stray low bits)."""
    if any(c not in B64_ALPHABET for c in text) or len(text) % 4 == 1:
        raise BackupRefused(error)
    data = base64.b64decode(text + b"=" * (-len(text) % 4))
    if b64_unpadded(data) != text:
        raise BackupRefused(error)
    return data


def b64_decode_padded(text, error):
    """Decode canonical padded base64 (the armor's), or refuse with `error`."""
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise BackupRefused(error)
    if base64.b64encode(data) != text:
        raise BackupRefused(error)
    return data


def age_is_armored(data):
    """Armor if, after leading ASCII whitespace, the input starts with '-----BEGIN'; anything else is read as
    a binary file."""
    return data.lstrip(BACKUP_WHITESPACE).startswith(b"-----BEGIN")


def armor_line(data, at):
    """(the line at `at` without its LF, CRLF or, at the end of the input, final CR; where the next line
    starts; whether it ended in LF)."""
    end = data.find(b"\n", at)
    line, following, ended = (data[at:], len(data), False) if end < 0 else (data[at:end], end + 1, True)
    return (line[:-1] if line.endswith(b"\r") else line), following, ended


def age_dearmor(data):
    """The binary file inside strict armor (spec "armor"), or Backup(Armor). The BEGIN line is the first line,
    with no whitespace before it."""
    refused = "Backup(Armor)"
    line, at, ended = armor_line(data, 0)
    if line != AGE_ARMOR_BEGIN or not ended:
        raise BackupRefused(refused)
    body = []
    while True:
        if at >= len(data):
            raise BackupRefused(refused)
        line, at, ended = armor_line(data, at)
        if line == AGE_ARMOR_END:
            break
        if not ended:
            raise BackupRefused(refused)
        body.append(line)
    if data[at:].lstrip(BACKUP_WHITESPACE) or len(data) - at >= BACKUP_ARMOR_WHITESPACE_BYTES or not body:
        raise BackupRefused(refused)
    if any(len(line) != AGE_COLUMNS for line in body[:-1]) or not 1 <= len(body[-1]) <= AGE_COLUMNS:
        raise BackupRefused(refused)
    return b64_decode_padded(b"".join(body), refused)


def age_parse_header(binary):
    """(stanzas as (arguments, body), the header up to and including '---', the MAC, the payload), or
    Backup(Header) (spec "header")."""
    refused = "Backup(Header)"
    if not binary.startswith(AGE_VERSION_LINE):
        raise BackupRefused(refused)
    at = len(AGE_VERSION_LINE)
    stanzas = []
    while not binary.startswith(b"--- ", at):
        end = binary.find(b"\n", at)
        if not binary.startswith(b"-> ", at) or end < 0:
            raise BackupRefused(refused)
        arguments = binary[at + 3:end].split(b" ")
        if any(not a or any(c < 0x21 or c > 0x7E for c in a) for a in arguments):
            raise BackupRefused(refused)
        at = end + 1
        body = b""
        while True:
            end = binary.find(b"\n", at)
            if end < 0:
                raise BackupRefused(refused)
            line = binary[at:end]
            if len(line) > AGE_COLUMNS or any(c not in B64_ALPHABET for c in line):
                raise BackupRefused(refused)
            body += line
            at = end + 1
            if len(line) < AGE_COLUMNS:
                break
        stanzas.append((arguments, b64_decode_unpadded(body, refused)))
    mac_end = at + 4 + 43
    if not stanzas or binary[mac_end:mac_end + 1] != b"\n":
        raise BackupRefused(refused)
    mac = b64_decode_unpadded(binary[at + 4:mac_end], refused)
    return stanzas, binary[:at + 3], mac, binary[mac_end + 1:]


def age_scrypt_stanza(stanzas):
    """(salt, log2 N, body) of the one scrypt stanza (spec "scrypt_stanza"), all before any scrypt work."""
    if not any(arguments[0] == b"scrypt" for arguments, _ in stanzas):
        raise BackupRefused("WrongPassphrase")  # no match: no stanza for a passphrase
    if len(stanzas) != 1 or len(stanzas[0][0]) != 3:
        raise BackupRefused("Backup(Header)")
    (_, salt_text, work_factor), body = stanzas[0]
    salt = b64_decode_unpadded(salt_text, "Backup(Header)")
    if len(salt) != AGE_SALT_BYTES or not re.fullmatch(rb"[1-9][0-9]?", work_factor) or len(body) != 32:
        raise BackupRefused("Backup(Header)")
    if int(work_factor) > BACKUP_MAX_WORK_FACTOR:
        raise BackupRefused("Backup(WorkFactor)")
    return salt, int(work_factor), body


def age_payload_nonce(chunk_index, final):
    """The STREAM nonce: an 11-byte big-endian chunk counter, then 0x01 for the final chunk."""
    return chunk_index.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def age_decrypt(data, passphrase):
    """The plaintext of an armored or binary age file under `passphrase` (spec "reader"), or BackupRefused."""
    if len(data) > BACKUP_MAX_FILE_BYTES:
        raise BackupRefused("Backup(TooLarge)")
    binary = age_dearmor(data) if age_is_armored(data) else data
    stanzas, header, mac, payload = age_parse_header(binary)
    salt, log_n, body = age_scrypt_stanza(stanzas)
    if not AGE_NONCE_BYTES + 16 <= len(payload) <= AGE_NONCE_BYTES + BACKUP_MAX_CHUNK_BYTES + 16:
        raise BackupRefused("Backup(Payload)")
    file_key = chacha20poly1305_open(age_wrap_key(passphrase, salt, log_n), bytes(12), body)
    if file_key is None:
        raise BackupRefused("WrongPassphrase")
    header_mac = hmac.new(hkdf_sha256(file_key, b"", AGE_HEADER_INFO), header, hashlib.sha256).digest()
    if not hmac.compare_digest(header_mac, mac):
        raise BackupRefused("Backup(HeaderMac)")
    nonce = payload[:AGE_NONCE_BYTES]
    plaintext = chacha20poly1305_open(hkdf_sha256(file_key, nonce, AGE_PAYLOAD_INFO), age_payload_nonce(0, True),
                                      payload[AGE_NONCE_BYTES:])
    if plaintext is None:
        raise BackupRefused("Backup(Payload)")
    return plaintext


def backup_fingerprint(words):
    """The master key fingerprint of S with the empty passphrase: what the plaintext names."""
    return bip32_fingerprint(bip32_master(bip39_seed(" ".join(words)))[0])


def backup_plaintext(words, fingerprint, app, version):
    """The plaintext v1 text (spec "plaintext")."""
    lines = [BACKUP_VERSION_LINE, "words: " + " ".join(words), "braille:"] + backup_braille_lines(words)
    lines += ["fingerprint: " + fingerprint.hex(), "created-by: keepcrypt-%s %d.%d.%d" % ((app,) + tuple(version))]
    return "".join(line + "\n" for line in lines)


_BIP39_INDEX = {}


def bip39_index(word):
    """The 0-based list index of a BIP39 English word, or None."""
    if not _BIP39_INDEX:
        _BIP39_INDEX.update((w, i) for i, w in enumerate(BIP39_ENGLISH))
    return _BIP39_INDEX.get(word)


def bip39_checksum_valid(words):
    """True if 12 or 24 list words carry a valid BIP39 checksum."""
    indices = [bip39_index(w) for w in words]
    if len(words) not in (12, 24) or None in indices:
        return False
    value = 0
    for index in indices:
        value = (value << 11) | index
    checksum_bits = len(words) * 11 // 33
    entropy = (value >> checksum_bits).to_bytes((len(words) * 11 - checksum_bits) // 8, "big")
    return bip39_words(entropy) == list(words)


def backup_plaintext_parse(data):
    """(words, fingerprint, app, version) of a plaintext v1, or BackupRefused (spec "plaintext_reader")."""
    refused = "Backup(Plaintext)"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise BackupRefused(refused)
    lines = text.split("\n")
    if lines[0] != BACKUP_VERSION_LINE:
        if re.fullmatch(r"keepcrypt-backup/v[1-9][0-9]*", lines[0]):
            raise BackupRefused("Backup(UnsupportedVersion)")
        raise BackupRefused(refused)
    if len(lines) < 3 or not lines[1].startswith("words: "):
        raise BackupRefused(refused)
    words = lines[1][len("words: "):].split(" ")
    created = re.fullmatch(r"created-by: keepcrypt-(pi|android|ios) (0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})"
                           r"\.(0|[1-9][0-9]{0,4})", lines[-2])
    if not bip39_checksum_valid(words) or created is None:
        raise BackupRefused(refused)
    version = tuple(int(created.group(i)) for i in (2, 3, 4))
    if max(version) > 0xFFFF:
        raise BackupRefused(refused)
    fingerprint = backup_fingerprint(words)
    if backup_plaintext(words, fingerprint, created.group(1), version).encode("utf-8") != data:
        raise BackupRefused(refused)
    return words, fingerprint, created.group(1), version


# --- Embedded known answers (tasks/todo.md, M2 group 3) ---------------------------------------
# Every command recomputes these before anything else and stops with exit 1 if one differs (CLAUDE.md
# rule 3, as core's session-start suite does), so a copy whose hashing, word list, seed, seal or braille
# code is broken refuses to run. Each value is a literal copied from the file and entry its comment
# names; vectorgen.py check 12 compares every value with that source, and runs a copy with one value of
# each group changed, which must fail that group.
KNOWN_ANSWERS = {
    "hash": {
        # vectors/kat.json "sha256", entries "empty", "abc" and "two-block": (message_ascii, digest_hex).
        "sha256": (
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ),
        # vectors/kat.json "sha512", entries "empty", "abc" and "two-block": (message_ascii, digest_hex).
        "sha512": (
            ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                 "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            ("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
             "mnopqrstnopqrstu",
             "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
             "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
        ),
        # vectors/kat.json "hmac", entry "rfc4231-case-2": (key_ascii, data_ascii, hmac_sha256_hex).
        "hmac_sha256": (
            ("Jefe", "what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        ),
    },
    "bip39": {
        # docs/seal-watchonly-braille.md "Sources": the official list's SHA-256, over the 2,048 words
        # joined by LF plus a final LF.
        "list_sha256": "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
        # vectors/bip39/vectors.json "english", entries 12 (12 words) and 14 (24 words): (entropy, mnemonic).
        "vectors": (
            ("9e885d952ad362caeb4efe34a8e91bd2",
             "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"),
            ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
             "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel "
             "tennis maple dilemma loan word shrug inflict delay length"),
        ),
    },
    "seed": {
        # vectors/keepcrypt.json "commitment" entry "d-00-1f" (c_hex) and "mixed" entry
        # "d-00-1f-coldcard-50" (the rest): D to C, then D and R to E and the words.
        "mixed": {
            "d_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "c_hex": "21778a7463cef10741413d0b80909a1045ba902d6244f519d2520e247cbe2e8c",
            "rolls": "12345612345612345612345612345612345612345612345612",
            "e_hex": "b2e18e2cdeb6f07e9dd5d3df8e315fa609fd2ebfe543387a483828553da6eee2",
            "words_12": ("real", "arrest", "menu", "runway", "humor", "dismiss", "jar", "risk", "test", "immense",
                         "fitness", "erupt"),
            "words_24": ("real", "arrest", "menu", "runway", "humor", "dismiss", "jar", "risk", "test", "immense",
                         "fitness", "equal", "panther", "nuclear", "zebra", "position", "debris", "spoil", "asthma",
                         "expose", "fatigue", "square", "romance", "elite"),
        },
        # vectors/coldcard/rolls.json, the case "123456" (Coldcard's published example): R to E
        # (sha256_hex) and the words.
        "dice_only": {
            "rolls": "123456",
            "e_hex": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            "words_12": ("mirror", "reject", "rookie", "talk", "pudding", "throw", "happy", "era", "myth", "already",
                         "payment", "owner"),
            "words_24": ("mirror", "reject", "rookie", "talk", "pudding", "throw", "happy", "era", "myth", "already",
                         "payment", "own", "sentence", "push", "head", "sting", "video", "explain", "letter", "bomb",
                         "casual", "hotel", "rather", "garment"),
        },
    },
    # vectors/seal.json, vector 1: CLAUDE.md's seal test vector and go-ahead vector, field by field.
    "seal": {
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "seed_prefix_hex": "5eb00bbddcf069084889a8ab91555681",
        "seal_code": "JXP3R-DXYAC-JZ1NA-X3RGQ-DJCJJN",
        "seal_tag_hex": "2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c",
        "seal_id": "5E0G7J6X",
        "seal_id_braille": "⠼⠑⠰⠑⠼⠚⠰⠛⠼⠛⠰⠚⠼⠋⠭",
        "lookup_prefix": "2b810",
        "colour_index": 3,
        "colour_hex": "#009E73",
        "grid": ("#......#", "...##...", "........", "..####..", "##....##", "#......#", "##.##.##", "##.##.##"),
        "go_ahead": {"nonce_hex": "0001020304050607", "code": "CF94-BCAJ"},
    },
    "braille": {
        # vectors/braille.json "cells" "table_sha256": SHA-256 of the canonical cell table text.
        "table_sha256": "fd75c236d2ab92e0fe682d502a5b4bf2537f78d5ec5630b2bac20a963ece9c9d",
        # vectors/braille.json "words", the entries for CLAUDE.md's braille cross-check vectors, field by field.
        "words": (
            {"number": 1, "word": "abandon", "faces": ("a", "b", "a", "n", "d"), "lighter_face": 5,
             "mirror_partners": (None, None, None, None, "f"), "cells": "⠁⠃⠁⠝⠙⠕⠝"},
            {"number": 20, "word": "act", "faces": ("a", "c", "t", None, None), "lighter_face": None,
             "mirror_partners": (None, None, None, None, None), "cells": "⠁⠉⠞"},
            {"number": 21, "word": "action", "faces": ("a", "c", "t", "i", "o"), "lighter_face": 5,
             "mirror_partners": (None, None, None, "e", None), "cells": "⠁⠉⠞⠊⠕⠝"},
            {"number": 1121, "word": "metal", "faces": ("m", "e", "t", "a", "l"), "lighter_face": 5,
             "mirror_partners": (None, "i", None, None, None), "cells": "⠍⠑⠞⠁⠇"},
            {"number": 2018, "word": "wire", "faces": ("w", "i", "r", "e", None), "lighter_face": None,
             "mirror_partners": ("r", "e", "w", "i", None), "cells": "⠺⠊⠗⠑"},
            {"number": 2048, "word": "zoo", "faces": ("z", "o", "o", None, None), "lighter_face": None,
             "mirror_partners": (None, None, None, None, None), "cells": "⠵⠕⠕"},
        ),
    },
}


def known_answers_hash(values):
    """The hash group: the names of the values that differ."""
    failed = []
    for name, algorithm in (("sha256", hashlib.sha256), ("sha512", hashlib.sha512)):
        failed += ["%s %d" % (name, n) for n, (message, digest) in enumerate(values[name], 1)
                   if algorithm(message.encode("ascii")).hexdigest() != digest]
    failed += ["hmac_sha256 %d" % n for n, (key, data, mac) in enumerate(values["hmac_sha256"], 1)
               if hmac.new(key.encode("ascii"), data.encode("ascii"), hashlib.sha256).hexdigest() != mac]
    return failed


def known_answers_bip39(values):
    """The bip39 group: the embedded list against its published hash, and the encoder."""
    failed = []
    if hashlib.sha256(("\n".join(BIP39_ENGLISH) + "\n").encode("ascii")).hexdigest() != values["list_sha256"]:
        failed.append("list_sha256")
    failed += ["vectors %d" % n for n, (entropy, mnemonic) in enumerate(values["vectors"], 1)
               if bip39_words(bytes.fromhex(entropy)) != mnemonic.split(" ")]
    return failed


def known_answers_seed(values):
    """The seed group: C from D, E and the words in mixed mode, and dice-only E and words. For 12 words the
    seed bits are E[0:16]."""
    d = bytes.fromhex(values["mixed"]["d_hex"])
    entropy = {"mixed": mixed_entropy(d, values["mixed"]["rolls"]),
               "dice_only": dice_only_entropy(values["dice_only"]["rolls"])}
    failed = [] if commitment(d).hex() == values["mixed"]["c_hex"] else ["mixed c_hex"]
    for mode, e in entropy.items():
        got = {"e_hex": e.hex(), "words_12": tuple(bip39_words(e[:16])), "words_24": tuple(bip39_words(e))}
        failed += ["%s %s" % (mode, key) for key, value in got.items() if values[mode][key] != value]
    return failed


def known_answers_seal(values):
    """The seal group: S from the mnemonic, the seal code, T, the Seal ID and its braille, the lookup
    prefix, the colour, the grid, and the go-ahead code for T and the nonce."""
    seed = bip39_seed(values["mnemonic"])
    code = seal_code(seed)
    tag = seal_tag(code)
    index, colour = seal_colour(tag)
    got = {
        "seed_prefix_hex": seed[:16].hex(),
        "seal_code": grouped(code, (5, 5, 5, 5, 6)),
        "seal_tag_hex": tag.hex(),
        "seal_id": seal_id(tag),
        "seal_id_braille": braille_text(seal_id(tag).lower()),
        "lookup_prefix": lookup_prefix(tag),
        "colour_index": index,
        "colour_hex": colour,
        "grid": tuple(seal_grid(tag)),
    }
    failed = [key for key, value in got.items() if values[key] != value]
    go = values["go_ahead"]
    if grouped(go_ahead_code(tag, bytes.fromhex(go["nonce_hex"])), (4, 4)) != go["code"]:
        failed.append("go_ahead")
    return failed


def known_answers_braille(values):
    """The braille group: the cell table's digest, and each word's SeedBook number, faces, lighter face,
    mirror partners and cells."""
    failed = []
    if hashlib.sha256(braille_table_text().encode("utf-8")).hexdigest() != values["table_sha256"]:
        failed.append("table_sha256")
    partner = braille_mirror_partner()
    for entry in values["words"]:
        word = entry["word"]
        faces = seedbook_faces(word)
        got = {
            "number": bip39_index(word) + 1,
            "word": word,
            "faces": tuple(faces),
            "lighter_face": SEEDBOOK_LIGHTER_FACE if faces[SEEDBOOK_LIGHTER_FACE - 1] else None,
            "mirror_partners": tuple(partner.get(face) if face else None for face in faces),
            "cells": braille_text(word),
        }
        failed += ["%s %s" % (word, key) for key, value in got.items() if entry.get(key) != value]
        failed += ["%s %s" % (word, key) for key in entry if key not in got]
    return failed


# The groups in the order selftest prints them; group 4 adds urls and insert, and group 7 adds run.
KNOWN_ANSWER_GROUPS = (
    ("hash", known_answers_hash),
    ("bip39", known_answers_bip39),
    ("seed", known_answers_seed),
    ("seal", known_answers_seal),
    ("braille", known_answers_braille),
)


def known_answers():
    """Every known-answer group recomputed: [(group, the names of the values that differ)], in
    KNOWN_ANSWER_GROUPS order. A group whose values cannot be read, or that has no values or no check,
    fails like a wrong value; the caller stops either way, so nothing here continues past a failure."""
    results = []
    for group, check in KNOWN_ANSWER_GROUPS:
        try:
            failed = check(KNOWN_ANSWERS[group])
        except Exception:  # a malformed or missing value fails its group, with no traceback
            failed = ["unreadable"]
        results.append((group, failed))
    checked = [group for group, _ in KNOWN_ANSWER_GROUPS]
    results += [(group, ["no check"]) for group in KNOWN_ANSWERS if group not in checked]
    return results


def command_selftest():
    """verify.py selftest: one line per known-answer group; 0 if all pass, else 1, naming each failing
    group."""
    results = known_answers()
    for group, failed in results:
        print("FAIL %s: %s" % (group, ", ".join(failed)) if failed else "ok   %s" % group)
    failing = [group for group, failed in results if failed]
    if failing:
        print("selftest FAILED: %s" % ", ".join(failing))
        return 1
    print("selftest passed: %d known-answer groups" % len(results))
    return 0


def main(argv):
    """The commands: selftest (tasks/todo.md, M2 group 7 adds mixed and dice). Anything else prints the
    usage, never the arguments, and returns 2."""
    if argv != ["selftest"]:
        print("usage: python3 -I verify.py selftest", file=sys.stderr)
        return 2
    return command_selftest()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
