var AWS = require('../core');

/**
 * @api private
 */
var cachedSecret = {};

/**
 * @api private
 */
var cacheQueue = [];

/**
 * @api private
 */
var maxCacheEntries = 50;

/**
 * @api private
 */
var v4Identifier = 'aws4_request';

module.exports = {
  /**
   * @api private
   *
   * @param date [String]
   * @param region [String]
   * @param serviceName [String]
   * @return [String]
   */
  createScope: function createScope(date, region, serviceName) {
    return [
      date.substr(0, 8),
      region,
      serviceName,
      v4Identifier
    ].join('/');
  },

  /**
   * @api private
   *
   * @param credentials [Credentials]
   * @param date [String]
   * @param region [String]
   * @param service [String]
   * @param shouldCache [Boolean]
   * @param signingKey
   * @param getSigningKey
   * @param finish
   */
  getSigningKey: function getSigningKey(
    credentials,
    date,
    region,
    service,
    shouldCache,
    signingKey,
    getSigningKey,
    finish
  ) {
    var cacheKey = [date, region, service].join('_');
    shouldCache = shouldCache !== false;
    if (shouldCache && (cacheKey in cachedSecret)) {
      finish(cachedSecret[cacheKey]);
      return;
    }
    // 已经有 signingKey
    if (signingKey) {
      if (shouldCache) {
        cachedSecret[cacheKey] = signingKey;
        cacheQueue.push(cacheKey);
        if (cacheQueue.length > maxCacheEntries) {
          // remove the oldest entry (not the least recently used)
          delete cachedSecret[cacheQueue.shift()];
        }
      }
      finish(signingKey);
      return;
    }
    // 获取 signingKey 函数
    if (getSigningKey) {
      getSigningKey(date, function (sk) {
        if (shouldCache) {
          cachedSecret[cacheKey] = sk;
          cacheQueue.push(cacheKey);
          if (cacheQueue.length > maxCacheEntries) {
            // remove the oldest entry (not the least recently used)
            delete cachedSecret[cacheQueue.shift()];
          }
        }
        finish(sk);
      });
      return;
    }

    var kDate = AWS.util.crypto.hmac(
      'AWS4' + credentials.secretAccessKey,
      date,
      'buffer'
    );
    var kRegion = AWS.util.crypto.hmac(kDate, region, 'buffer');
    var kService = AWS.util.crypto.hmac(kRegion, service, 'buffer');

    var _signingKey = AWS.util.crypto.hmac(kService, v4Identifier, 'buffer');
    if (shouldCache) {
      cachedSecret[cacheKey] = _signingKey;
      cacheQueue.push(cacheKey);
      if (cacheQueue.length > maxCacheEntries) {
        // remove the oldest entry (not the least recently used)
        delete cachedSecret[cacheQueue.shift()];
      }
    }

    finish(_signingKey);
  },

  /**
   * @api private
   *
   * Empties the derived signing key cache. Made available for testing purposes
   * only.
   */
  emptyCache: function emptyCache() {
    cachedSecret = {};
    cacheQueue = [];
  }
};
