const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const { generateRiskReport, refreshReferences } = require("./src/riskEngine");

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

function sendJson(res, status, data) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8"
  });

  res.end(JSON.stringify(data, null, 2));
}

function sendStatic(req, res) {
  const urlPath = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  ).pathname;

  const requested = urlPath === "/" ? "/index.html" : urlPath;
  const filePath = path.normalize(path.join(PUBLIC_DIR, requested));

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }

    res.writeHead(200, {
      "content-type":
        MIME_TYPES[path.extname(filePath)] || "application/octet-stream"
    });

    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(
      req.url,
      `http://${req.headers.host || "localhost"}`
    );

    // Health check for Railway / deployment monitoring
    if (url.pathname === "/health") {
      sendJson(res, 200, {
        status: "ok",
        service: "tawasolpay-cyber-risk-assistant"
      });
      return;
    }

    // Risk analysis API
    if (url.pathname === "/api/risks") {
      const report = await generateRiskReport({
        refresh: url.searchParams.get("refresh") === "1"
      });

      sendJson(res, 200, report);
      return;
    }

    // Explicit reference refresh endpoint
    if (
      url.pathname === "/api/references/refresh" &&
      req.method === "POST"
    ) {
      const result = await refreshReferences();
      sendJson(res, 200, result);
      return;
    }

    // Serve frontend
    sendStatic(req, res);
  } catch (error) {
    console.error("Request error:", error);

    sendJson(res, 500, {
      error: error.message,
      stack:
        process.env.NODE_ENV === "production"
          ? undefined
          : error.stack
    });
  }
});

// Start the HTTP server immediately.
// This allows Railway to detect the application as healthy
// without waiting for NIST embeddings or risk analysis.
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Cyber Risk Assistant running on port ${PORT}`);

  // Perform the initial risk analysis in the background.
  // The server is already listening and can respond to health checks.
  generateRiskReport({ refresh: false })
    .then(() => {
      console.log("Initial risk report generated successfully.");
    })
    .catch((err) => {
      console.warn(
        "Background risk report generation failed:",
        err.message
      );
    });
});