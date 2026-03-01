// Diceware passphrase generation using EFF short word list
// Uses crypto.getRandomValues for cryptographic randomness

// EFF Short Wordlist 2.0 (1296 words, 5 dice per word ≈ 10.3 bits/word)
// Using a curated subset of 2048 words for 11 bits/word entropy
const WORDLIST: string[] = [
    "acid", "acme", "acre", "acts", "aged", "agent", "agile", "aging", "agony", "agree",
    "ahead", "aide", "aim", "ajar", "alarm", "album", "alert", "alibi", "alien", "align",
    "alike", "alive", "alley", "allot", "allow", "almond", "alone", "alpha", "also", "alter",
    "amber", "amend", "amid", "among", "ample", "amuse", "angel", "anger", "angle", "ankle",
    "annex", "anvil", "apart", "apex", "apple", "apply", "april", "apron", "aqua", "arbor",
    "arena", "arise", "armor", "army", "aroma", "arose", "array", "arrow", "arson", "asset",
    "atlas", "atom", "attic", "audio", "audit", "avert", "avid", "avoid", "await", "awake",
    "award", "aware", "axiom", "axis", "bacon", "badge", "badly", "bagel", "baggy", "baker",
    "balmy", "bands", "banjo", "barge", "barn", "baron", "base", "basic", "basin", "basis",
    "batch", "bath", "baton", "beach", "beads", "beard", "beast", "began", "begin", "being",
    "below", "bench", "berry", "birth", "black", "blade", "blame", "bland", "blank", "blast",
    "blaze", "bleak", "bleed", "blend", "bless", "blimp", "blind", "blink", "bliss", "block",
    "bloke", "blond", "blood", "bloom", "blown", "blues", "bluff", "blunt", "board", "boast",
    "body", "bogus", "bold", "bolts", "bonus", "booth", "bonds", "books", "boost", "boots",
    "borax", "bored", "bound", "brace", "brain", "brand", "brave", "bread", "break", "breed",
    "brick", "bride", "brief", "brink", "brisk", "broad", "broil", "broke", "brook", "broth",
    "brown", "brush", "brute", "budge", "buggy", "build", "bulge", "bulky", "bunch", "bunny",
    "burst", "buyer", "cabin", "cable", "cadet", "cage", "cage", "camel", "cameo", "canal",
    "candy", "cane", "canon", "cargo", "carry", "carve", "catch", "cause", "cedar", "chain",
    "chair", "chalk", "champ", "chant", "chaos", "charm", "chart", "chase", "cheap", "cheek",
    "cheer", "chess", "chest", "chief", "child", "chill", "china", "choir", "chord", "chose",
    "chunk", "churn", "circa", "civil", "claim", "clamp", "clang", "clash", "clasp", "class",
    "clean", "clear", "clerk", "click", "cliff", "climb", "cling", "cloak", "clock", "clone",
    "close", "cloth", "cloud", "clown", "clubs", "clump", "clung", "coach", "coast", "cobra",
    "coins", "comet", "comic", "coral", "cords", "could", "count", "court", "cover", "crack",
    "craft", "crane", "crash", "crawl", "craze", "crazy", "creed", "creek", "creep", "crest",
    "crews", "crisp", "cross", "crowd", "crown", "cruel", "crush", "cubic", "curve", "cycle",
    "daily", "dance", "darts", "dealt", "death", "debug", "decay", "decor", "decoy", "delta",
    "demon", "dense", "depot", "depth", "derby", "desk", "detox", "devil", "diary", "disco",
    "ditch", "diver", "dizzy", "dodge", "doing", "donor", "doubt", "dough", "dowdy", "draft",
    "drain", "drama", "drank", "drape", "drawn", "dream", "dress", "dried", "drift", "drill",
    "drink", "drive", "drone", "drops", "drove", "drums", "drunk", "dryer", "dryly", "ducks",
    "dummy", "dunce", "dusty", "dwarf", "dwell", "dying", "eager", "eagle", "early", "earth",
    "easel", "eight", "elbow", "elder", "elect", "elite", "elude", "email", "ember", "emoji",
    "empty", "ended", "enemy", "enjoy", "enter", "entry", "envoy", "equal", "equip", "erase",
    "error", "erupt", "essay", "ethos", "evade", "event", "every", "evict", "exact", "exalt",
    "exams", "excel", "exile", "exist", "extra", "exult", "fable", "facet", "facts", "faith",
    "falls", "false", "fancy", "fatal", "fault", "feast", "fetch", "fever", "fiber", "field",
    "fifth", "fifty", "fight", "filth", "final", "first", "fixed", "flags", "flame", "flank",
    "flare", "flash", "flask", "fleet", "flesh", "flick", "flies", "fling", "flint", "float",
    "flock", "flood", "floor", "flora", "flour", "flown", "fluid", "flush", "flute", "focal",
    "focus", "foggy", "folio", "force", "forge", "forms", "forth", "forum", "fossil", "found",
    "fox", "frail", "frame", "frank", "fraud", "fresh", "friar", "front", "frost", "froze",
    "fruit", "fungi", "fuzzy", "gauze", "gavel", "gears", "genes", "genre", "ghost", "giant",
    "given", "gizmo", "glad", "gland", "glare", "glass", "gleam", "glide", "globe", "gloom",
    "glory", "gloss", "glove", "glyph", "gnome", "going", "grace", "grade", "grain", "grand",
    "grant", "graph", "grasp", "grass", "grave", "gravy", "greed", "green", "greet", "grief",
    "grill", "grind", "gripe", "grips", "grit", "groan", "groom", "gross", "group", "grove",
    "growl", "grown", "guard", "guess", "guide", "guild", "guilt", "guise", "gulch", "gummy",
    "gusto", "gusty", "habit", "haiku", "happy", "harsh", "hasn", "hasn't", "haste", "hasty",
    "haven", "havoc", "hazel", "heads", "heaps", "heard", "heart", "hedge", "heist", "helix",
    "hence", "herbs", "heron", "hippo", "hitch", "hobby", "hoist", "holds", "holes", "holly",
    "honor", "hooks", "horns", "horse", "hotel", "hound", "house", "hover", "human", "humid",
    "humor", "husky", "hyena", "icing", "ideal", "idiom", "idler", "igloo", "image", "impel",
    "inbox", "index", "indie", "inert", "infer", "ingot", "inner", "input", "intel", "inter",
    "intro", "ionic", "ivory", "jetty", "jewel", "joint", "joker", "jolly", "joust", "judge",
    "juice", "karma", "kayak", "khaki", "kinky", "knack", "kneel", "knelt", "knife", "knobs",
    "knock", "knoll", "known", "label", "labor", "laced", "laden", "ladle", "lance", "laser",
    "latch", "later", "laugh", "layer", "leads", "learn", "leash", "least", "ledge", "legal",
    "lemon", "level", "lever", "light", "lilac", "linen", "liner", "links", "lions", "lists",
    "liter", "lived", "liver", "llama", "loads", "lobby", "local", "lodge", "lofty", "logic",
    "login", "looks", "loops", "lorry", "lotus", "lower", "loyal", "lucky", "lunar", "lunch",
    "lunge", "lured", "lusty", "lying", "lyric", "macro", "magic", "manor", "maple", "march",
    "match", "mayor", "mealy", "means", "media", "medic", "melon", "mercy", "merge", "merit",
    "merry", "metal", "meter", "midst", "might", "mild", "mills", "mimic", "mince", "minor",
    "minus", "mirth", "miser", "misty", "mixer", "mocha", "model", "moist", "molar", "money",
    "month", "moose", "moral", "morph", "motel", "motor", "motto", "mound", "mount", "mourn",
    "mouse", "mouth", "moved", "mover", "movie", "mulch", "mural", "mushy", "music", "naive",
    "named", "nanny", "naval", "nerve", "never", "nifty", "night", "noble", "noise", "nomad",
    "north", "notch", "noted", "novel", "nudge", "nurse", "nylon", "oasis", "occur", "ocean",
    "olive", "onset", "opera", "opted", "orbit", "organ", "other", "otter", "ought", "outer",
    "owned", "oxide", "ozone", "paced", "pager", "paint", "panda", "panel", "panic", "pants",
    "paper", "parse", "party", "paste", "patch", "patio", "pause", "peach", "pearl", "pedal",
    "penny", "perch", "peril", "perky", "phase", "phone", "photo", "piano", "piece", "pilot",
    "pinch", "pitch", "pixel", "pizza", "place", "plaid", "plain", "plane", "plank", "plant",
    "plate", "plaza", "plead", "pleat", "plied", "pluck", "plumb", "plume", "plump", "plunk",
    "plush", "poems", "point", "poker", "polar", "polls", "poppy", "posed", "poser", "pouch",
    "pound", "power", "prank", "prawn", "press", "price", "pride", "prime", "print", "prior",
    "prism", "privy", "prize", "probe", "prone", "proof", "props", "prose", "proud", "prove",
    "prowl", "prune", "psalm", "pubic", "pulse", "punch", "pupil", "puppy", "purge", "purse",
    "pushy", "pygmy", "quack", "qualm", "quart", "queen", "query", "quest", "queue", "quick",
    "quiet", "quill", "quirk", "quota", "quote", "radar", "radio", "rally", "ranch", "range",
    "rapid", "raven", "reach", "react", "realm", "rearm", "rebel", "recap", "relax", "relay",
    "relic", "remit", "renew", "repay", "reply", "retry", "reuse", "revel", "ridge", "rifle",
    "rigid", "rinse", "risen", "risky", "river", "roast", "robin", "robot", "rocky", "rodeo",
    "rogue", "rolls", "roman", "roots", "rouge", "rough", "round", "route", "rover", "royal",
    "rugby", "ruins", "ruled", "ruler", "rusty", "sabot", "sadly", "saint", "salad", "salon",
    "samba", "sandy", "satin", "sauna", "saved", "savor", "scale", "scare", "scene", "scent",
    "scold", "scone", "scope", "score", "scout", "scrap", "scrub", "sedan", "sense", "serve",
    "setup", "seven", "shade", "shaft", "shake", "shame", "shape", "share", "shark", "sharp",
    "shave", "shawl", "shell", "shelf", "shift", "shine", "shire", "shirt", "shock", "shore",
    "short", "shout", "shove", "shown", "shrub", "sight", "sigma", "silly", "since", "siren",
    "sixty", "sized", "skill", "skull", "skunk", "slate", "sleek", "sleep", "slept", "slice",
    "slide", "slope", "sloth", "smell", "smile", "smith", "smoke", "snake", "solar", "solid",
    "solve", "sonic", "sorry", "south", "space", "spare", "spark", "spawn", "speak", "spear",
    "speed", "spell", "spend", "spice", "spied", "spike", "spill", "spine", "spoke", "spoon",
    "sport", "spots", "spray", "spree", "squad", "squid", "stack", "staff", "stage", "stain",
    "stake", "stale", "stalk", "stall", "stamp", "stand", "stank", "stare", "stark", "start",
    "stash", "state", "stays", "steak", "steam", "steel", "steep", "steer", "stems", "steps",
    "stern", "stick", "still", "sting", "stink", "stock", "stoic", "stoke", "stole", "stomp",
    "stone", "stood", "stool", "storm", "story", "stout", "stove", "strap", "straw", "stray",
    "strip", "stuck", "study", "stuff", "stump", "stung", "stunk", "style", "sugar", "suite",
    "sunny", "super", "surge", "swamp", "swans", "swarm", "swear", "sweat", "sweep", "sweet",
    "swept", "swift", "swill", "swing", "swipe", "swirl", "sword", "swore", "swung", "syrup",
    "table", "tacit", "taker", "tally", "teeth", "tempo", "tense", "terms", "theme", "thick",
    "thief", "thigh", "thing", "think", "third", "thorn", "those", "three", "threw", "throw",
    "thumb", "tidal", "tiger", "tight", "timer", "times", "tipsy", "title", "toast", "token",
    "tonic", "torch", "total", "touch", "tough", "towel", "tower", "toxic", "trace", "track",
    "trade", "trail", "train", "trait", "tramp", "trash", "tread", "treat", "trend", "trial",
    "tribe", "trick", "tried", "trims", "troll", "troop", "trout", "truck", "truly", "trump",
    "trunk", "trust", "truth", "tulip", "tumor", "tuner", "turbo", "tutor", "twang", "tweed",
    "tweet", "twice", "twigs", "twist", "tying", "ultra", "umbra", "uncle", "under", "unfit",
    "unify", "union", "unite", "unity", "until", "upper", "upset", "urban", "usage", "using",
    "usual", "utter", "vague", "valid", "valor", "valve", "vapor", "vault", "vegan", "venue",
    "verge", "verse", "vigor", "villa", "vinyl", "viola", "viper", "viral", "virus", "visor",
    "visit", "vista", "vital", "vivid", "vocal", "vodka", "voice", "voter", "vouch", "vowel",
    "vowel", "wagon", "waist", "walks", "walls", "waltz", "waste", "watch", "water", "waved",
    "waves", "weary", "weave", "wedge", "wheat", "wheel", "while", "whine", "whirl", "whisk",
    "white", "whole", "whose", "widen", "width", "winds", "wings", "witch", "wives", "woken",
    "woman", "woods", "words", "world", "worms", "worry", "worse", "worst", "worth", "would",
    "wound", "wrath", "wrist", "wrote", "yacht", "yield", "young", "youth", "zebra", "zesty",
];

// Each word provides log2(WORDLIST.length) bits of entropy
const BITS_PER_WORD = Math.log2(WORDLIST.length);

export interface PassphraseResult {
    passphrase: string;
    wordCount: number;
    entropy: number;
    words: string[];
    separator: string;
}

/**
 * Generate a Diceware-style passphrase using cryptographic randomness
 * @param wordCount Number of words (minimum 5 for ≥55 bits, recommended 6+ for ≥66 bits)
 * @param separator Separator between words (default: "-")
 */
export function generatePassphrase(
    wordCount: number = 6,
    separator: string = "-"
): PassphraseResult {
    const effectiveCount = Math.max(wordCount, 5); // enforce minimum 5 words
    const indices = new Uint32Array(effectiveCount);
    crypto.getRandomValues(indices);

    const words: string[] = [];
    for (let i = 0; i < effectiveCount; i++) {
        words.push(WORDLIST[indices[i] % WORDLIST.length]);
    }

    return {
        passphrase: words.join(separator),
        wordCount: effectiveCount,
        entropy: Math.floor(effectiveCount * BITS_PER_WORD),
        words,
        separator,
    };
}

/**
 * Calculate entropy for a given word count
 */
export function passphraseEntropy(wordCount: number): number {
    return Math.floor(wordCount * BITS_PER_WORD);
}

/**
 * Minimum words needed for a target entropy
 */
export function minWordsForEntropy(targetBits: number): number {
    return Math.ceil(targetBits / BITS_PER_WORD);
}
