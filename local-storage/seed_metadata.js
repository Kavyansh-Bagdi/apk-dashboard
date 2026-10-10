
const dbName = "apkDB";
const collectionName = "metadata";
const targetDB = db.getSiblingDB(dbName);

// The provided record contains array counts, but not the actual array values.
// These helpers preserve the reported lengths using clearly marked placeholders.
function placeholders(prefix, count) {
  return Array.from(
    { length: count },
    (_, i) => `${prefix}_${String(i + 1).padStart(2, "0")}`
  );
}

// Define a schema for the metadata collection.
const validator = {
  $jsonSchema: {
    bsonType: "object",
    required: [
      "sha256",
      "package_name",
      "permissions",
      "is_vulnerable",
      "dex_date",
      "file_size_bytes",
      "vt_score",
      "added_date",
      "activities",
      "api_calls",
      "num_strings",
      "receivers",
      "services",
      "malware_family",
      "min_sdk_version",
      "target_sdk_version",
      "num_classes",
      "num_api_calls",
      "num_permissions",
      "static_features_extracted",
      "valid_apk",
      "vulnerability_types",
      "source_dataset",
      "is_dummy"
    ],
    properties: {
      sha256: {
        bsonType: "string",
        pattern: "^[a-fA-F0-9]{64}$"
      },
      package_name: { bsonType: "string" },
      permissions: { bsonType: "array", items: { bsonType: "string" } },
      is_vulnerable: { bsonType: "bool" },
      dex_date: { bsonType: "date" },
      file_size_bytes: { bsonType: "long" },
      vt_score: { bsonType: "int", minimum: 0 },
      added_date: { bsonType: "date" },
      activities: { bsonType: "array", items: { bsonType: "string" } },
      api_calls: { bsonType: "array", items: { bsonType: "string" } },
      num_strings: { bsonType: "int", minimum: 0 },
      receivers: { bsonType: "array", items: { bsonType: "string" } },
      services: { bsonType: "array", items: { bsonType: "string" } },
      malware_family: { bsonType: "array", items: { bsonType: "string" } },
      file_size_mib: { bsonType: "double", minimum: 0 },
      min_sdk_version: { bsonType: "int", minimum: 1 },
      target_sdk_version: { bsonType: "int", minimum: 1 },
      num_classes: { bsonType: "int", minimum: 0 },
      num_activities: { bsonType: "int", minimum: 0 },
      num_receivers: { bsonType: "int", minimum: 0 },
      num_services: { bsonType: "int", minimum: 0 },
      num_permissions: { bsonType: "int", minimum: 0 },
      num_api_calls: { bsonType: "int", minimum: 0 },
      static_features_extracted: { bsonType: "bool" },
      security_attribute_result: { bsonType: "string" },
      valid_apk: { bsonType: "bool" },
      vulnerability_flag: { bsonType: "bool" },
      vulnerability_types: { bsonType: "array", items: { bsonType: "string" } },
      source_dataset: { bsonType: "string" },
      is_dummy: { bsonType: "bool" }
    }
  }
};

// Create the collection if it does not already exist.
// Otherwise, update its validator without deleting existing data.
const exists = targetDB
  .getCollectionInfos({ name: collectionName }).length > 0;

if (!exists) {
  targetDB.createCollection(collectionName, { validator });
} else {
  targetDB.runCommand({
    collMod: collectionName,
    validator,
    validationLevel: "strict",
    validationAction: "error"
  });
}

const metadata = targetDB.getCollection(collectionName);

// One unique index per APK SHA256.
metadata.createIndex({ sha256: 1 }, { unique: true });

// Upsert prevents duplicate copies when the script is run again.
function saveRecord(record) {
  metadata.updateOne(
    { sha256: record.sha256 },
    { $setOnInsert: record },
    { upsert: true }
  );
}

// Original record supplied by you.
const realRecord = {
  sha256: "0000A6D452D58424A8B7613F175AF5937F590033616B808BF8C0445695F82541",
  package_name: "com.maatto.quack.ncr",

  permissions: placeholders("permission", 21),
  is_vulnerable: true,
  dex_date: ISODate("2020-01-03T17:46:36Z"),
  file_size_bytes: NumberLong("15548117"),
  vt_score: 14,
  added_date: ISODate("2022-05-06T22:41:53Z"),

  activities: placeholders("activity", 9),
  api_calls: placeholders("api_call", 82),
  num_strings: 1257,
  receivers: placeholders("receiver", 1),
  services: placeholders("service", 1),

  malware_family: ["Adware", "Trojan"],
  file_size_mib: 14.83,
  min_sdk_version: 14,
  target_sdk_version: 26,
  num_classes: 7,
  num_activities: 9,
  num_api_calls: 2972,
  num_receivers: 1,
  num_services: 1,
  num_permissions: 21,

  static_features_extracted: true,
  security_attribute_result: "Result",
  valid_apk: true,
  vulnerability_flag: true,
  vulnerability_types: [],
  source_dataset: "0a819a7a7c77b9793ea8fdfa96d129d3ad6944c604e4372a9072d563b25266fc",

  is_dummy: false
};

saveRecord(realRecord);

// Ten synthetic records for development and AG Grid testing.
const packages = [
  "com.example.photoeditor",
  "com.example.weatherapp",
  "com.example.filemanager",
  "com.example.qrscanner",
  "com.example.musicplayer",
  "com.example.flashlight",
  "com.example.notes",
  "com.example.videoplayer",
  "com.example.cleaner",
  "com.example.launcher"
];

const families = [
  ["Adware"],
  ["Trojan"],
  ["Adware", "Trojan"],
  ["Spyware"],
  ["Ransomware"],
  ["Banker"],
  ["Dropper"],
  ["Adware"],
  ["Trojan"],
  []
];

for (let i = 0; i < 10; i++) {
  const n = i + 1;

  // Valid, unique 64-character hexadecimal test identifier.
  const sha256 = n.toString(16).padStart(64, "0").toUpperCase();

  const permissionCount = 5 + (i % 17);
  const activityCount = 1 + (i % 9);
  const receiverCount = i % 4;
  const serviceCount = i % 3;
  const apiArrayCount = 10 + i * 3;
  const sizeBytes = 1_000_000 + i * 1_234_567;
  const numApiCalls = 200 + i * 275;
  const vtScore = (i * 3) % 71;

  const record = {
    sha256,
    package_name: packages[i],

    permissions: placeholders("android.permission.TEST", permissionCount),
    is_vulnerable: i % 3 !== 0,
    dex_date: ISODate(`2024-0${1 + (i % 9)}-15T10:30:00Z`),
    file_size_bytes: NumberLong(String(sizeBytes)),
    vt_score: vtScore,
    added_date: ISODate(`2025-0${1 + (i % 9)}-10T12:00:00Z`),

    activities: placeholders("com.example.Activity", activityCount),
    api_calls: placeholders("Landroid/example;->method", apiArrayCount),
    num_strings: 300 + i * 123,
    receivers: placeholders("com.example.Receiver", receiverCount),
    services: placeholders("com.example.Service", serviceCount),

    malware_family: families[i],
    file_size_mib: Number((sizeBytes / (1024 * 1024)).toFixed(2)),
    min_sdk_version: 21,
    target_sdk_version: 28 + (i % 9),
    num_classes: 20 + i * 13,
    num_activities: activityCount,
    num_api_calls: numApiCalls,
    num_receivers: receiverCount,
    num_services: serviceCount,
    num_permissions: permissionCount,

    static_features_extracted: true,
    security_attribute_result: "Synthetic test result",
    valid_apk: true,
    vulnerability_flag: i % 3 !== 0,
    vulnerability_types: i % 3 === 0 ? [] : ["Synthetic test finding"],
    source_dataset: "synthetic-test-dataset",

    is_dummy: true
  };

  saveRecord(record);
}

print(`Database: ${dbName}`);
print(`Collection: ${collectionName}`);
print(`Total documents: ${metadata.countDocuments()}`);
print(`Dummy documents: ${metadata.countDocuments({ is_dummy: true })}`);
print(`Real documents: ${metadata.countDocuments({ is_dummy: false })}`);
