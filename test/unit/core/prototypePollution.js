"use strict";

import assert from "assert";
import http from "http";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter from "../../../lib/adapters/http.js";

const startServer = (body, contentType) =>
  new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        res.writeHead(200, {
          "Content-Type": contentType || "text/plain",
          Connection: "close",
        });
        res.end(
          typeof body === "function" ? body(Buffer.concat(chunks)) : body,
        );
      });
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });

const stopServer = (server) =>
  new Promise((resolve) => server.close(() => resolve()));

const serverURL = (server) => "http://127.0.0.1:" + server.address().port + "/";

// A config object as the http adapter receives it after mergeConfig:
// only own properties, no defaults applied.
const adapterConfig = (url, extra) =>
  Object.assign(
    { url, method: "get", headers: {}, proxy: false, maxRedirects: 0 },
    extra,
  );

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.headers;
    delete Object.prototype.proxy;
    delete Object.prototype.responseType;
    delete Object.prototype.responseEncoding;
    delete Object.prototype.transitional;
    delete Object.prototype.response;
    delete Object.prototype.url;
    delete Object.prototype.data;
    delete Object.prototype.httpVersion;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });

    it("should not pick up a polluted value for a key owned only by config1", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({ transport: undefined }, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false,
      );
    });

    it("should not let polluted transformRequest/transformResponse replace the defaults", function () {
      const hijack = function hijack() {
        return "hijacked";
      };
      Object.prototype.transformRequest = [hijack];
      Object.prototype.transformResponse = [hijack];

      const result = mergeConfig(defaults, { url: "/a" });

      assert.strictEqual(
        result.transformRequest.length,
        defaults.transformRequest.length,
      );
      assert.strictEqual(result.transformRequest[0], defaults.transformRequest[0]);
      assert.strictEqual(
        result.transformResponse.length,
        defaults.transformResponse.length,
      );
      assert.strictEqual(
        result.transformResponse[0],
        defaults.transformResponse[0],
      );
    });

    it("should not merge polluted headers into the request config", function () {
      Object.prototype.headers = { "X-Injected": "evil" };

      const result = mergeConfig(defaults, { url: "/a" });

      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.headers, "X-Injected"),
        false,
      );
      assert.strictEqual(result.headers["X-Injected"], undefined);
    });

    it("should not take a polluted url for a key owned only by config1", function () {
      Object.prototype.url = "http://attacker.example/";
      const result = mergeConfig({ url: "/a" }, {});
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "url"),
        false,
      );
    });

    it("should not merge polluted values into a key owned only by config2", function () {
      Object.prototype.proxy = { host: "attacker.example", port: 8080 };

      const result = mergeConfig(defaults, {
        url: "/a",
        proxy: { protocol: "http" },
      });

      assert.strictEqual(result.proxy.protocol, "http");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.proxy, "host"),
        false,
      );
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.proxy, "port"),
        false,
      );
    });
  });

  describe("defaults.transformRequest", function () {
    it("should ignore a polluted formSerializer", function () {
      let visited = false;
      Object.prototype.formSerializer = {
        visitor: function () {
          visited = true;
          return false;
        },
      };
      const headers = new AxiosHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
      });

      const result = defaults.transformRequest[0].call({}, { a: "b" }, headers);

      assert.strictEqual(visited, false);
      assert.strictEqual(result, "a=b");
    });

    it("should ignore a polluted env.FormData", function () {
      let constructed = false;
      function EvilFormData() {
        constructed = true;
        this.append = function () {};
      }
      Object.prototype.env = { FormData: EvilFormData };
      const headers = new AxiosHeaders({
        "Content-Type": "multipart/form-data",
      });

      const result = defaults.transformRequest[0].call({}, { a: "b" }, headers);

      assert.strictEqual(constructed, false);
      assert.strictEqual(result instanceof EvilFormData, false);
    });
  });

  describe("defaults.transformResponse", function () {
    it("should ignore a polluted parseReviver", function () {
      Object.prototype.parseReviver = function (key, value) {
        return key === "role" ? "admin" : value;
      };

      const result = defaults.transformResponse[0].call({}, '{"role":"user"}');

      assert.strictEqual(result.role, "user");
    });

    it("should ignore a polluted responseType", function () {
      Object.prototype.responseType = "text";

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should ignore a polluted transitional", function () {
      Object.prototype.transitional = { forcedJSONParsing: false };

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not attach a polluted response to a JSON parse error", function () {
      Object.prototype.response = { status: 299, data: "evil" };
      let error;

      try {
        defaults.transformResponse[0].call(
          { responseType: "json", transitional: { silentJSONParsing: false } },
          "{not json",
        );
      } catch (err) {
        error = err;
      }

      assert.ok(error);
      assert.strictEqual(error.code, "ERR_BAD_RESPONSE");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(error, "response"),
        false,
      );
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(error, "status"),
        false,
      );
    });
  });

  describe("http adapter", function () {
    let server;

    afterEach(async function () {
      if (server) {
        await stopServer(server);
        server = null;
      }
    });

    it("should not use a polluted transport", async function () {
      server = await startServer("ok");
      let hijacked = null;
      Object.prototype.transport = {
        request: function (options, cb) {
          hijacked = options;
          return http.request(options, cb);
        },
      };

      const res = await httpAdapter(
        adapterConfig(serverURL(server), {
          auth: { username: "svc_account", password: "hunter2" },
        }),
      );

      assert.strictEqual(hijacked, null);
      assert.strictEqual(res.data, "ok");
    });

    it("should not send a polluted data as the request body", async function () {
      server = await startServer((body) => "body:" + body.toString());
      Object.prototype.data = "smuggled";

      const res = await httpAdapter(adapterConfig(serverURL(server)));

      assert.strictEqual(res.data, "body:");
    });

    it("should not use a polluted httpVersion", async function () {
      server = await startServer("ok");
      Object.prototype.httpVersion = "bogus";

      const res = await httpAdapter(adapterConfig(serverURL(server)));

      assert.strictEqual(res.data, "ok");
    });

    it("should not use a polluted responseType", async function () {
      server = await startServer("hello");
      Object.prototype.responseType = "arraybuffer";

      const res = await httpAdapter(adapterConfig(serverURL(server)));

      assert.strictEqual(res.data, "hello");
    });

    it("should not use a polluted responseEncoding", async function () {
      server = await startServer("hello");
      Object.prototype.responseEncoding = "base64";

      const res = await httpAdapter(adapterConfig(serverURL(server)));

      assert.strictEqual(res.data, "hello");
    });

    it("should not use a polluted env.Blob for data: URIs", async function () {
      let constructed = false;
      function EvilBlob() {
        constructed = true;
      }
      Object.prototype.env = { Blob: EvilBlob };

      try {
        await httpAdapter(
          adapterConfig("data:text/plain;base64,aGVsbG8=", {
            responseType: "blob",
          }),
        );
      } catch (err) {
        // Blob is not available on every supported Node.js version; a
        // rejection here is fine as long as the polluted class was not used.
      }

      assert.strictEqual(constructed, false);
    });

    it("should not let a polluted parseReviver tamper with JSON responses", async function () {
      server = await startServer('{"role":"user"}', "application/json");
      Object.prototype.parseReviver = function (key, value) {
        return key === "role" ? "admin" : value;
      };

      const res = await axios.get(serverURL(server), { proxy: false });

      assert.strictEqual(res.data.role, "user");
    });
  });
});
