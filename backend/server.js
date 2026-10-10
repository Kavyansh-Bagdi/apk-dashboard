
import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import * as Minio from "minio";
import archiver from "archiver";

const app = express();
const PORT = process.env.PORT || 5000;

const client = new MongoClient(process.env.MONGO_URI);
const dbName = process.env.DB_NAME || "apkDB";
const collectionName =
  process.env.COLLECTION_NAME || "metadata";

const minioClient = new Minio.Client({
  endPoint: process.env.MINIO_ENDPOINT || "127.0.0.1",
  port: Number(process.env.MINIO_PORT || 9000),
  useSSL: process.env.MINIO_USE_SSL === "true",
  accessKey: process.env.MINIO_ACCESS_KEY,
  secretKey: process.env.MINIO_SECRET_KEY,
});

const minioBucket = process.env.MINIO_BUCKET || "vulnerable-apks";
app.use(cors({
  origin: [
    "http://127.0.0.1:5173",
    "http://localhost:5173"
  ]
}));
app.use(express.json());

let metadata;

app.get("/api/health", async (req, res) => {
  try {
    await client.db("admin").command({ ping: 1 });
    res.json({ status: "ok", database: dbName });
  } catch {
    res.status(503).json({ status: "error" });
  }
});

app.get("/api/metadata", async (req, res) => {
  try {
    const limit = Math.min(
      Math.max(Number(req.query.limit) || 1000, 1),
      5000
    );

    const skip = Math.max(Number(req.query.skip) || 0, 0);
    const filter = {};

    if (req.query.is_dummy === "true") {
      filter.is_dummy = true;
    } else if (req.query.is_dummy === "false") {
      filter.is_dummy = false;
    }

    if (req.query.is_vulnerable === "true") {
      filter.is_vulnerable = true;
    } else if (req.query.is_vulnerable === "false") {
      filter.is_vulnerable = false;
    }

    if (
      typeof req.query.search === "string" &&
      req.query.search.trim()
    ) {
      const term = req.query.search.trim().slice(0, 150);
      const escaped = term.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      );

      filter.$or = [
        { package_name: { $regex: escaped, $options: "i" } },
        { sha256: { $regex: escaped, $options: "i" } },
        { source_dataset: { $regex: escaped, $options: "i" } },
        {
          malware_family: {
            $elemMatch: {
              $regex: escaped,
              $options: "i"
            }
          }
        }
      ];
    }

    const [documents, total] = await Promise.all([
      metadata
        .find(filter)
        .sort({ added_date: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      metadata.countDocuments(filter)
    ]);

    const data = documents.map((doc) => ({
      ...doc,
      _id: doc._id.toString()
    }));

    res.json({ data, total, limit, skip });
  } catch (error) {
    console.error("Metadata API error:", error);
    res.status(500).json({
      error: "Unable to fetch metadata"
    });
  }
});


app.post("/api/apks/download", async (req, res) => {
  try {
    const { sha256s } = req.body;

    if (
      !Array.isArray(sha256s) ||
      sha256s.length === 0 ||
      sha256s.length > 100
    ) {
      return res.status(400).json({
        error: "Provide between 1 and 100 object names.",
      });
    }

    if (
      !sha256s.every(
        (hash) =>
          typeof hash === "string" &&
          /^[a-fA-F0-9]{1,128}$/.test(hash)
      )
    ) {
      return res.status(400).json({
        error: "Each identifier must contain hexadecimal characters only.",
      });
    }

    const identifiers = [...new Set(sha256s)];

    // Example: "12345" -> "12345.apk"
    const objectNames = identifiers.map(
      (hash) => `${hash}.apk`
    );

    // Check that all requested objects exist before starting the ZIP.
    const streams = await Promise.all(
      objectNames.map(async (objectName) => {
        const stat = await minioClient.statObject(
          minioBucket,
          objectName
        );

        return {
          objectName,
          size: stat.size,
        };
      })
    );

    // Open streams after validating all object names.
    const files = await Promise.all(
      streams.map(async (file) => ({
        ...file,
        stream: await minioClient.getObject(
          minioBucket,
          file.objectName
        ),
      }))
    );

    const archive = archiver("zip", {
      zlib: { level: 6 },
    });

    archive.on("error", (error) => {
      console.error("ZIP creation failed:", error);

      if (!res.headersSent) {
        res.status(500).json({
          error: "Failed to create ZIP archive.",
        });
      } else {
        res.destroy(error);
      }
    });

    for (const file of files) {
      file.stream.on("error", (error) => {
        archive.emit("error", error);
      });
    }

    res.setHeader("Content-Type", "application/zip");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="selected-apks.zip"'
    );

    archive.pipe(res);

    for (const file of files) {
      // Preserve the original object name inside the ZIP.
      archive.append(file.stream, {
        name: file.objectName,
      });
    }

    res.on("close", () => {
      if (!res.writableEnded) {
        archive.abort();
        files.forEach((file) => file.stream.destroy());
      }
    });

    await archive.finalize();
  } catch (error) {
    console.error("APK download error:", error);

    if (!res.headersSent) {
      const status =
        error.code === "NotFound" ||
        error.code === "NoSuchKey" ||
        error.statusCode === 404
          ? 404
          : 500;

      res.status(status).json({
        error:
          status === 404
            ? "One or more APK objects were not found in MinIO."
            : "Unable to download APKs.",
      });
    } else {
      res.destroy(error);
    }
  }
});


async function start() {
  if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is missing from backend/.env");
  }

  await client.connect();

  metadata = client.db(dbName).collection(collectionName);

  await client.db("admin").command({ ping: 1 });

  app.listen(PORT, () => {
    console.log(`API running at http://localhost:${PORT}`);
    console.log(`Collection: ${dbName}.${collectionName}`);
  });
}

start().catch((error) => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
