"use strict";

import assert from "assert";
import http from "http";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter from "../../../lib/adapters/http.js";
import validator from "../../../lib/helpers/validator.js";
import resolveConfig from "../../../lib/helpers/resolveConfig.js";

const nodeMajorVersion = parseInt(process.versions.node.split('.')[0], 10);

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
    delete Object.prototype.validateStatus;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.adapter;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.fetchOptions;
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

  // GHSA-w9j2-pvgh-6h63: mergeDirectKeys must not inherit validateStatus from
  // Object.prototype (was using the `in` operator which traverses the chain).
  describe("GHSA-w9j2-pvgh-6h63 validateStatus merge", function () {
    const startStatusServer = (status) =>
      new Promise((resolve) => {
        const server = http.createServer((req, res) => {
          res.writeHead(status, {
            "Content-Type": "application/json",
            Connection: "close",
          });
          res.end('{"error":"unauthorized"}');
        });
        server.listen(0, "127.0.0.1", () => resolve(server));
      });

    let server;

    afterEach(async function () {
      if (server) {
        await stopServer(server);
        server = null;
      }
    });

    it("should not inherit a polluted validateStatus during mergeConfig", function () {
      Object.prototype.validateStatus = () => true;

      const merged = mergeConfig(defaults, { url: "/x" });

      assert.strictEqual(merged.validateStatus, defaults.validateStatus);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(merged, "validateStatus"),
        true,
      );
      assert.strictEqual(merged.validateStatus(401), false);
      assert.strictEqual(merged.validateStatus(500), false);
    });

    it("should keep a validateStatus owned only by config1 when Object.prototype.validateStatus is polluted", function () {
      const validateStatus = function (status) {
        return status === 200;
      };
      Object.prototype.validateStatus = () => true;

      const merged = mergeConfig({ validateStatus }, {});

      assert.strictEqual(merged.validateStatus, validateStatus);
    });

    it("should still honor an explicit validateStatus from config2", function () {
      const custom = function (status) {
        return status < 500;
      };
      Object.prototype.validateStatus = () => true;

      assert.strictEqual(
        mergeConfig(defaults, { validateStatus: custom }).validateStatus,
        custom,
      );
      assert.strictEqual(
        mergeConfig(defaults, { validateStatus: null }).validateStatus,
        null,
      );
    });

    it("should keep 4xx/5xx responses rejected when Object.prototype.validateStatus is polluted", async function () {
      server = await startStatusServer(401);
      Object.prototype.validateStatus = () => true;

      let threw = false;
      try {
        await axios.get(serverURL(server), { proxy: false });
      } catch (err) {
        threw = true;
        assert.strictEqual(err.response.status, 401);
        assert.strictEqual(err.code, "ERR_BAD_REQUEST");
      }
      assert.strictEqual(threw, true);
    });

    it("should keep 5xx responses rejected for instances created after Object.prototype.validateStatus is polluted", async function () {
      server = await startStatusServer(500);
      Object.prototype.validateStatus = () => true;

      const instance = axios.create();

      assert.strictEqual(
        instance.defaults.validateStatus,
        defaults.validateStatus,
      );

      let threw = false;
      try {
        await instance.get(serverURL(server), { proxy: false });
      } catch (err) {
        threw = true;
        assert.strictEqual(err.response.status, 500);
        assert.strictEqual(err.code, "ERR_BAD_RESPONSE");
      }
      assert.strictEqual(threw, true);
    });
  });

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and resolveConfig, bypassing hasOwnProperty and
  // allowing prototype pollution gadgets (auth, baseURL, socketPath,
  // beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj resolveConfig baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });

    // resolveConfig is what the xhr and fetch adapters use to build the final
    // request URL and Authorization header.
    it('should not resolve the URL against a polluted baseURL in resolveConfig', function () {
      Object.prototype.baseURL = 'http://attacker.example';

      const resolved = resolveConfig({ url: '/api', method: 'get', headers: {} });

      assert.strictEqual(resolved.url, '/api');
    });

    it('should not set an Authorization header from a polluted auth in resolveConfig', function () {
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const resolved = resolveConfig({ url: '/api', method: 'get', headers: {} });

      assert.strictEqual(resolved.headers.get('Authorization'), undefined);
    });
  });

  // The http adapter must read the gadget properties as own properties even
  // when it is handed a plain config object (e.g. one copied by a request
  // interceptor) rather than the null-prototype object built by mergeConfig.
  describe('GHSA-q8qp-cvcw-x6jj http adapter own-property reads', function () {
    const startEchoServer = (handler) =>
      new Promise((resolve) => {
        const srv = http.createServer(handler || ((req, res) => {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            Connection: 'close',
          });
          res.end(JSON.stringify({ url: req.url, headers: req.headers }));
        }));
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });

    const servers = [];

    afterEach(async function () {
      while (servers.length) {
        await stopServer(servers.pop());
      }
    });

    it('should not send a polluted auth as an Authorization header', async function () {
      const server = await startEchoServer();
      servers.push(server);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const res = await httpAdapter(adapterConfig(serverURL(server) + 'api'));
      const body = JSON.parse(res.data);

      assert.strictEqual(body.url, '/api');
      assert.strictEqual(body.headers.authorization, undefined);
    });

    it('should not connect to a polluted socketPath', async function () {
      const server = await startEchoServer();
      servers.push(server);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const res = await httpAdapter(adapterConfig(serverURL(server) + 'api'));

      assert.strictEqual(JSON.parse(res.data).url, '/api');
    });

    it('should not invoke a polluted beforeRedirect while following redirects', async function () {
      const target = await startEchoServer();
      servers.push(target);
      const redirector = await startEchoServer((req, res) => {
        res.writeHead(302, { Location: serverURL(target) + 'final', Connection: 'close' });
        res.end();
      });
      servers.push(redirector);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const res = await httpAdapter(
        adapterConfig(serverURL(redirector) + 'start', { maxRedirects: 5 }),
      );

      assert.strictEqual(JSON.parse(res.data).url, '/final');
      assert.strictEqual(hijackCalled, false);
    });

    it('should not pass a polluted insecureHTTPParser to http.request', async function () {
      const server = await startEchoServer();
      servers.push(server);
      Object.prototype.insecureHTTPParser = true;

      let captured = 'not called';
      const origRequest = http.request;
      http.request = function (options) {
        captured = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      try {
        await httpAdapter(adapterConfig(serverURL(server)));
      } finally {
        http.request = origRequest;
      }

      assert.strictEqual(captured, false);
    });
  });

  // GHSA-3g43-6gmg-66jw: assertOptions looked validators up with a plain
  // property read on the schema, so a polluted Object.prototype.<option> was
  // invoked as a validator with the whole request config (credential theft),
  // or crashed every request when it was not a function (DoS).
  describe('GHSA-3g43-6gmg-66jw validator.assertOptions', function () {
    let server;

    afterEach(async function () {
      if (server) {
        await stopServer(server);
        server = null;
      }
    });

    it('should not use an inherited Object.prototype value as a validator', function () {
      Object.prototype.polluted = 'not a function';

      assert.doesNotThrow(function () {
        validator.assertOptions({ polluted: 1 }, {}, true);
      });
    });

    it('should not hand the request config to a polluted transformResponse', async function () {
      server = await startServer('{"ok":true}', 'application/json');
      let invoked = false;
      let leaked;
      Object.prototype.transformResponse = function polluted(value, opt, options) {
        invoked = true;
        leaked = options && options.auth;
        return true;
      };

      const res = await axios.get(serverURL(server), {
        proxy: false,
        auth: { username: 'svc_account', password: 'hunter2' },
      });

      assert.strictEqual(invoked, false);
      assert.strictEqual(leaked, undefined);
      assert.strictEqual(res.data.ok, true);
    });

    it('should not break requests when Object.prototype.transformResponse is not a function', async function () {
      server = await startServer('{"ok":true}', 'application/json');
      Object.prototype.transformResponse = ['not a function'];

      const res = await axios.get(serverURL(server), { proxy: false });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.data.ok, true);
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });
  });
});
