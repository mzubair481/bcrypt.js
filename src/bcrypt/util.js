/**
 * Continues with the callback on the next tick.
 * @function
 * @param {function(...[*])} callback Callback to execute
 * @inner
 */

// Use Promise-based deferral as primary method, with setTimeout as fallback
var nextTick = (function() {
    if (typeof Promise === 'function') {
        return function(fn) {
            Promise.resolve().then(function() { fn(); });
        };
    }
    return function(fn) {
        setTimeout(fn, 0);
    };
})();

//? include("util/utf8.js");

/**
 * Converts a JavaScript string to UTF8 bytes.
 * @function
 * @param {string} str String
 * @returns {!Array.<number>} UTF8 bytes
 * @inner
 */
var stringToBytes = utf8Array;

//? include("util/base64.js");

Date.now = Date.now || function() { return +new Date; };
