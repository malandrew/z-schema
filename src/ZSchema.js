/*
 * Copyright (c) 2013, Martin Zagora <zaggino@gmail.com>
 * Copyright (c) 2013, Oleksiy Krivoshey <oleksiyk@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @license http://opensource.org/licenses/MIT
 */

/*jslint node:true, nomen:true, plusplus:true, regexp:true, vars:true*/
/*jshint -W044*/
/*global ZSchema*/

(function () {
    'use strict';

    var Promise = require('bluebird');
    var request = require('request');

    // z-schema used Q before bluebird, so alias is here to preserve compatibility
    Promise.prototype.fail = Promise.prototype.catch;

    /***** ValidationError class *****/

    var ValidationError = function (code, message, params, path) {
        this.code    = code;
        this.message = message;
        this.path    = path || '';
        this.params  = params || {};
    };

    ValidationError.prototype = new Error();

    ValidationError.messages = {
        'INVALID_TYPE': 'invalid type: {type} (expected {expected})',
        'ENUM_MISMATCH': 'No enum match for: {value}',
        'ANY_OF_MISSING': 'Data does not match any schemas from "anyOf"',
        'ONE_OF_MISSING': 'Data does not match any schemas from "oneOf"',
        'ONE_OF_MULTIPLE': 'Data is valid against more than one schema from "oneOf"',
        'NOT_PASSED': 'Data matches schema from "not"',
        'UNRESOLVABLE_REFERENCE': 'Reference could not be resolved: {ref}',
        // Numeric errors
        'MULTIPLE_OF': 'Value {value} is not a multiple of {multipleOf}',
        'MINIMUM': 'Value {value} is less than minimum {minimum}',
        'MINIMUM_EXCLUSIVE': 'Value {value} is equal or less than exclusive minimum {minimum}',
        'MAXIMUM': 'Value {value} is greater than maximum {maximum}',
        'MAXIMUM_EXCLUSIVE': 'Value {value} is equal or greater than exclusive maximum {maximum}',
        // String errors
        'MIN_LENGTH': 'String is too short ({length} chars), minimum {minimum}',
        'MAX_LENGTH': 'String is too long ({length} chars), maximum {maximum}',
        'PATTERN': 'String does not match pattern: {pattern}',
        // Object errors
        'OBJECT_PROPERTIES_MINIMUM': 'Too few properties defined ({count}), minimum {minimum}',
        'OBJECT_PROPERTIES_MAXIMUM': 'Too many properties defined ({count}), maximum {maximum}',
        'OBJECT_REQUIRED': 'Missing required property: {property}',
        'OBJECT_ADDITIONAL_PROPERTIES': 'Additional properties not allowed',
        'OBJECT_DEPENDENCY_KEY': 'Dependency failed - key must exist: {missing} (due to key: {key})',
        // Array errors
        'ARRAY_LENGTH_SHORT': 'Array is too short ({length}), minimum {minimum}',
        'ARRAY_LENGTH_LONG': 'Array is too long ({length}), maximum {maximum}',
        'ARRAY_UNIQUE': 'Array items are not unique (indices {index1} and {index2})',
        'ARRAY_ADDITIONAL_ITEMS': 'Additional items not allowed',
        // Format errors
        'FORMAT': '{format} format validation failed: {error}',
        // Schema validation errors
        'KEYWORD_TYPE_EXPECTED': 'Keyword "{keyword}" is expected to be of type "{type}"',
        'KEYWORD_UNDEFINED_STRICT': 'Keyword "{keyword}" must be defined in strict mode',
        'KEYWORD_UNEXPECTED': 'Keyword "{keyword}" is not expected to appear in the schema',
        'KEYWORD_MUST_BE': 'Keyword "{keyword}" must be {expression}',
        'KEYWORD_DEPENDENCY': 'Keyword "{keyword1}" requires keyword "{keyword2}"',
        'KEYWORD_PATTERN': 'Keyword "{keyword}" is not a valid RegExp pattern ({pattern})',
        'KEYWORD_VALUE_TYPE': 'Each element of keyword "{keyword}" array must be a "{type}"',
        'UNKNOWN_FORMAT': 'There is no validation function for format "{format}"',
        // Remote errors
        'SCHEMA_NOT_REACHABLE': 'Validator was not able to read schema located at {uri}',
        'SCHEMA_TYPE_EXPECTED': 'Schema is expected to be of type "object"'
    };

    ValidationError.prototype.addSubError = function (err) {
        if (!this.subErrors) { this.subErrors = []; }
        this.subErrors.push(err);
    };

    ValidationError.createError = function (code, params, path) {
        var msg = ValidationError.messages[code];
        params  = params || {};

        if (typeof msg !== 'string') {
            throw new Error('Unknown error code: ' + code);
        }

        msg = msg.replace(/\{([^{}]*)\}/g, function (whole, varName) {
            var subValue = params[varName];
            if (typeof subValue === 'string' || typeof subValue === 'number') {
                return subValue;
            }
            if (subValue && typeof subValue.toString === 'function') {
                return subValue.toString();
            }
            return whole;
        });

        return new ValidationError(code, msg, params, path);
    };

    /***** Utility methods *****/

    function noop() {}

    function isBoolean (what) {
        return typeof what === 'boolean';
    }

    function isString (what) {
        return typeof what === 'string';
    }

    function isInteger (what) {
        return isNumber(what) && what % 1 === 0;
    }

    function isNumber (what) {
        return typeof what === 'number' && Number.isFinite(what);
    }

    function isArray (what) {
        return Array.isArray(what);
    }

    function isObject (what) {
        return typeof what === 'object' && what === Object(what) && !Array.isArray(what);
    }

    function isFunction (what) {
        return typeof what === 'function';
    }

    function whatIs (what) {
        if (what === undefined) {
            return 'undefined';
        } else if (what === null) {
            return 'null';
        } else if (isBoolean(what)) {
            return 'boolean';
        } else if (isString(what)) {
            return 'string';
        } else if (isArray(what)) {
            return 'array';
        } else if (isInteger(what)) {
            return 'integer';
        } else if (isNumber(what)) {
            return 'number';
        } else if (isObject(what)) {
            return 'object';
        } else if (isFunction(what)) {
            return 'function';
        } else if (Number.isNaN(what)) {
            return 'not-a-number';
        } else {
            throw new Error('whatIs does not know what this is: ' + what);
        }
    }

    function isUniqueArray (arr, match) {
        match = match || {};
        var i, j, l = arr.length;
        for (i = 0; i < l; i++) {
            for (j = i + 1; j < l; j++) {
                if (deepEqual(arr[i], arr[j])) {
                    match.index1 = i;
                    match.index2 = j;
                    return false;
                }
            }
        }
        return true;
    }

    function bracketify (index) {
        return '[' + index + ']';
    }

    function isAbsoluteUri (str) {
        return getRegExp('^https?\:\/\/').test(str);
    }

    function forEach (obj, callback, context) {
        if (Array.isArray(obj)) {
            return obj.forEach(callback, context);
        } else if (isObject(obj)) {
            var key;
            for (key in obj) {
                if (obj.hasOwnProperty(key)) {
                    callback.call(context, obj[key], key);
                }
            }
        }
    }

    function map (obj, callback, thisArg) {
        var index = -1,
            result = [];

        forEach(obj, function (val, key) {
            result[++index] = callback.call(thisArg, val, key);
        });

        return result;
    }

    function defaults (main, def) {
        forEach(def, function (val, key) {
            if (main[key] === undefined) {
                main[key] = val;
            }
        });
        return main;
    }

    function uniq (arr) {
        var rv = [];
        arr.forEach(function (val) {
            if (rv.indexOf(val) === -1) {
                rv.push(val);
            }
        });
        return rv;
    }

    function difference (bigSet, subSet) {
        var rv = [];
        bigSet.forEach(function (val) {
            if (subSet.indexOf(val) === -1) {
                rv.push(val);
            }
        });
        return rv;
    }

    function deepEqual (json1, json2) {
        // http://json-schema.org/latest/json-schema-core.html#rfc.section.3.6

        // Two JSON values are said to be equal if and only if:
        // both are nulls; or
        // both are booleans, and have the same value; or
        // both are strings, and have the same value; or
        // both are numbers, and have the same mathematical value; or
        if (json1 === json2) {
            return true;
        }

        var i, len;

        // both are arrays, and:
        if (isArray(json1) && isArray(json2)) {
            // have the same number of items; and
            if (json1.length !== json2.length) {
                return false;
            }
            // items at the same index are equal according to this definition; or
            len = json1.length;
            for (i = 0; i < len; i++) {
                if (!deepEqual(json1[i], json2[i])) {
                    return false;
                }
            }
            return true;
        }

        // both are objects, and:
        if (isObject(json1) && isObject(json2)) {
            // have the same set of property names; and
            var keys1 = Object.keys(json1);
            var keys2 = Object.keys(json2);
            if (!deepEqual(keys1, keys2)) {
                return false;
            }
            // values for a same property name are equal according to this definition.
            len = keys1.length;
            for (i = 0; i < len; i++) {
                if (!deepEqual(json1[keys1[i]], json2[keys1[i]])) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    function decodeJSONPointer (str) {
        // http://tools.ietf.org/html/draft-ietf-appsawg-json-pointer-07#section-3
        return decodeURIComponent(str).replace(/~[0-1]/g, function (x) {
            return x === '~1' ? '/' : '~';
        });
    }

    var _getRegExpCache = {};
    function getRegExp (pattern) {
        if (!_getRegExpCache[pattern]) {
            _getRegExpCache[pattern] = new RegExp(pattern);
        }
        return _getRegExpCache[pattern];
    }

    var _getRemoteSchemaCache = {};
    function getRemoteSchema (urlWithQuery, callback) {
        var url = urlWithQuery.split('#')[0];

        function returnSchemaFromString(str, url) {
            var sch;

            try {
                sch = JSON.parse(str);
            } catch (e) {
                delete _getRemoteSchemaCache[url];
                throw new Error('Not a JSON data at: ' + url + ', ' + e);
            }

            // override in case of 'lying' schemas?
            if (!sch.id) {
                sch.id = url;
            }
            if (!sch.$schema) {
                sch.$schema = url;
            }
            sch.__$downloadedFrom = url;
            return callback ? callback(undefined, sch) : sch;
        }

        if (_getRemoteSchemaCache[url]) {
            return returnSchemaFromString(_getRemoteSchemaCache[url], url);
        }

        if (!callback) {
            // sync mode, checking in cache only
            return;
        }

        request(url, function (error, response, body) {
            if (error) {
                callback(error);
                return;
            }
            returnSchemaFromString(_getRemoteSchemaCache[url] = body, url);
        });
    }

    function resolveSchemaId (schema, id) {
        if (!isObject(schema) && !isArray(schema)) {
            return;
        }
        if (schema.id === id) {
            return schema;
        }
        var rv = null;
        forEach(schema, function (val) {
            if (!rv) {
                rv = resolveSchemaId(val, id);
            }
        });
        return rv;
    }

    function resolveSchemaQuery(schema, rootSchema, queryStr, allowNull, sync, schemaCache) {
        expect.string(queryStr);
        if (queryStr === '#') {
            return rootSchema;
        }

        var rv = null;
        var uriPart = queryStr.split('#')[0];
        var queryPart = queryStr.split('#')[1];

        if (uriPart) {
            if (uriPart.indexOf('http:') === 0 || uriPart.indexOf('https:') === 0) {
                // remote
                if (!rootSchema.__remotes || !rootSchema.__remotes[uriPart]) {
                    if (!sync) {
                        throw new Error('Remote is not downloaded: ' + uriPart);
                    } else {
                        throw new Error('Use .setRemoteReference to download references in sync mode: ' + uriPart);
                    }
                }
                rv = rootSchema.__remotes[uriPart];
            } else {
                // it's a local ID
                rv = resolveSchemaId(rootSchema, uriPart);
            }
            if (!rv && isObject(schemaCache)) {
                rv = schemaCache[uriPart];
            }
        } else {
            rv = rootSchema;
        }

        // we have the schema and query to resolve in it
        if (rv && queryPart) {
            var queries = ('#' + queryPart).split('/');
            while (queries.length > 0) {
                var key = decodeJSONPointer(queries.shift());
                if (key.indexOf('#') === -1) {
                    rv = rv[key];
                } else if (key !== '#') {
                    rv = resolveSchemaId(rv, key);
                }
            }
        }

        if (!rv && !allowNull) {
            throw new Error('Could not resolve schema reference: ' + queryStr);
        }

        return rv;
    }

    /*
     * these functions are used to validate formats
     * method registerFormat is available for adding new formats
     */
    /*jshint maxlen: false*/
    var FormatValidators = {};

    FormatValidators['date'] = function (date) {
        if (!isString(date)) {
            return true;
        }
        // full-date from http://tools.ietf.org/html/rfc3339#section-5.6
        var matches = getRegExp('^([0-9]{4})-([0-9]{2})-([0-9]{2})$').exec(date);
        if (matches === null) {
            return false;
        }
        // var year = matches[1];
        var month = matches[2];
        var day = matches[3];
        if (month < '01' || month > '12' || day < '01' || day > '31') {
            return false;
        }
        return true;
    };

    FormatValidators['date-time'] = function (dateTime) {
        if (!isString(dateTime)) {
            return true;
        }
        // date-time from http://tools.ietf.org/html/rfc3339#section-5.6
        var s = dateTime.toLowerCase().split('t');
        if (!FormatValidators.date(s[0])) {
            return false;
        }
        var matches = getRegExp('^([0-9]{2}):([0-9]{2}):([0-9]{2})(.[0-9]+)?(z|([+-][0-9]{2}:[0-9]{2}))$').exec(s[1]);
        if (matches === null) {
            return false;
        }
        var hour = matches[1];
        var minute = matches[2];
        var second = matches[3];
        // var fraction = matches[4];
        // var timezone = matches[5];
        if (hour > '23' || minute > '59' || second > '59') {
            return false;
        }
        return true;
    };

    FormatValidators['email'] = function (email) {
        // http://fightingforalostcause.net/misc/2006/compare-email-regex.php
        return typeof email !== 'string' || getRegExp(/^[-a-z0-9~!$%^&*_=+}{\'?]+(\.[-a-z0-9~!$%^&*_=+}{\'?]+)*@([a-z0-9_][-a-z0-9_]*(\.[-a-z0-9_]+)*\.(aero|arpa|biz|com|coop|edu|gov|info|int|mil|museum|name|net|org|pro|travel|mobi|[a-z][a-z])|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(:[0-9]{1,5})?$/i).test(email);
    };

    FormatValidators['hostname'] = function (hostname) {
        if (!isString(hostname)) {
            return true;
        }
        /*
            http://json-schema.org/latest/json-schema-validation.html#anchor114
            A string instance is valid against this attribute if it is a valid
            representation for an Internet host name, as defined by RFC 1034, section 3.1 [RFC1034].

            http://tools.ietf.org/html/rfc1034#section-3.5

            <digit> ::= any one of the ten digits 0 through 9
            var digit = /[0-9]/;

            <letter> ::= any one of the 52 alphabetic characters A through Z in upper case and a through z in lower case
            var letter = /[a-zA-Z]/;

            <let-dig> ::= <letter> | <digit>
            var letDig = /[0-9a-zA-Z]/;

            <let-dig-hyp> ::= <let-dig> | "-"
            var letDigHyp = /[-0-9a-zA-Z]/;

            <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
            var ldhStr = /[-0-9a-zA-Z]+/;

            <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
            var label = /[a-zA-Z](([-0-9a-zA-Z]+)?[0-9a-zA-Z])?/;

            <subdomain> ::= <label> | <subdomain> "." <label>
            var subdomain = /^[a-zA-Z](([-0-9a-zA-Z]+)?[0-9a-zA-Z])?(\.[a-zA-Z](([-0-9a-zA-Z]+)?[0-9a-zA-Z])?)*$/;

            <domain> ::= <subdomain> | " "
            var domain = null;
        */
        var valid = getRegExp('^[a-zA-Z](([-0-9a-zA-Z]+)?[0-9a-zA-Z])?(\\.[a-zA-Z](([-0-9a-zA-Z]+)?[0-9a-zA-Z])?)*$').test(hostname);
        if (valid) {
            // the sum of all label octets and label lengths is limited to 255.
            if (hostname.length > 255) { return false; }
            // Each node has a label, which is zero to 63 octets in length
            var labels = hostname.split('.');
            for (var i = 0; i < labels.length; i++) { if (labels[i].length > 63) { return false; } }
        }
        return valid;
    };
    
    FormatValidators['host-name'] = function () {
        return FormatValidators.hostname.apply(this, arguments);
    };

    FormatValidators['ipv4'] = function (ipv4) {
        // https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository
        return typeof ipv4 !== 'string' || getRegExp('^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$').test(ipv4);
    };

    FormatValidators['ipv6'] = function (ipv6) {
        // Stephen Ryan at Dartware @ http://forums.intermapper.com/viewtopic.php?t=452
        return typeof ipv6 !== 'string' || getRegExp('^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$').test(ipv6);
    };

    FormatValidators['regex'] = function (str) {
        try {
            getRegExp(str);
            return true;
        } catch (e) {
            return false;
        }
    };

    FormatValidators['uri'] = function (uri, validator) {
        if (validator.options.strictUris) {
            return FormatValidators['strict-uri'].apply(this, arguments);
        }
        // https://github.com/zaggino/z-schema/issues/18
        // RegExp from http://tools.ietf.org/html/rfc3986#appendix-B
        return typeof uri !== 'string' || getRegExp('^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?').test(uri);
    };

    FormatValidators['strict-uri'] = function (uri) {
        // http://mathiasbynens.be/demo/url-regex
        // https://gist.github.com/dperini/729294
        return typeof uri !== 'string' || getRegExp(
            '^' +
                // protocol identifier
                '(?:(?:https?|ftp)://)' +
                // user:pass authentication
                '(?:\\S+(?::\\S*)?@)?' +
                '(?:' +
                    // IP address exclusion
                    // private & local networks
                    '(?!10(?:\\.\\d{1,3}){3})' +
                    '(?!127(?:\\.\\d{1,3}){3})' +
                    '(?!169\\.254(?:\\.\\d{1,3}){2})' +
                    '(?!192\\.168(?:\\.\\d{1,3}){2})' +
                    '(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})' +
                    // IP address dotted notation octets
                    // excludes loopback network 0.0.0.0
                    // excludes reserved space >= 224.0.0.0
                    // excludes network & broacast addresses
                    // (first & last IP address of each class)
                    '(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])' +
                    '(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}' +
                    '(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))' +
                '|' +
                    // host name
                    '(?:(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)' +
                    // domain name
                    '(?:\\.(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)*' +
                    // TLD identifier
                    '(?:\\.(?:[a-z\\u00a1-\\uffff]{2,}))' +
                ')' +
                // port number
                '(?::\\d{2,5})?' +
                // resource path
                '(?:/[^\\s]*)?' +
            '$', 'i'
        ).test(uri);
    };
    /*jshint maxlen: 150*/

    function capitaliseFirstLetter(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    function makeExpectFn(type) {
        var pred = eval("is" + capitaliseFirstLetter(type));
        return function (what) {
            if (!pred(what)) {
                var msg = 'Type mismatch, expected "' + type + '", got "' + whatIs(what) + '"';
                throw new Error(msg);
            }
        }
    }

    /**
     * Error utility methods
     */
    var expect = {};
    expect.boolean = makeExpectFn("boolean");
    expect.string = makeExpectFn("string");
    expect.callable = makeExpectFn("function");
    expect.object = makeExpectFn("object");

    var CustomFormatValidators = {};

    var Report = function (parentReport) {
        if (parentReport) {
            this.parentReport = parentReport;
            forEach(parentReport, function (val, key) {
                this[key] = val;
            }, this);
        }
        this.errors = [];
        this.warnings = [];
        this.path = [];
    };

    Report.prototype.getPath = function () {
        var path = ['#'];

        if (this.parentReport) {
            path = path.concat(this.parentReport.path);
        }
        path = path.concat(this.path);

        if (path.length == 1) {
            return '#/';
        }

        return path.join('/');
    };

    Report.prototype.addWarning = function (message) {
        this.warnings.push({
            message: message,
            path: this.getPath()
        });
        return true;
    };

    Report.prototype.addError = function (code, params, subReports) {
        var err = ValidationError.createError(code, params, this.getPath());
        if (subReports) {
            subReports.forEach(function (report) {
                report.errors.forEach(err.addSubError.bind(err));
            });
        }
        this.errors.push(err);
        return false;
    };

    Report.prototype.expect = function (bool, code, params, subReports) {
        if (!bool) {
            this.addError(code, params, subReports);
            return false;
        } else {
            return true;
        }
    };

    function makeTypeExpectFn(pred, typeString) {
        return function (value, keyword) {
            if (!pred(value)) {
                this.addError('KEYWORD_TYPE_EXPECTED', {
                    keyword: keyword, 
                    type: typeString
                });
                return false;
            } else {
                return true;
            }
        };
    }

    function makeMultipleTypesExpectFn(preds, typeStrings) {
        function anyPred (value) {
            return preds.some(function (pred) { return pred(value); });
        }
        return makeTypeExpectFn(anyPred, typeStrings);
    }

    Report.prototype.expectString = makeTypeExpectFn(isString, 'string');

    Report.prototype.expectNumber = makeTypeExpectFn(isNumber, 'number');

    Report.prototype.expectBoolean = makeTypeExpectFn(isBoolean, 'boolean');

    Report.prototype.expectInteger = makeTypeExpectFn(isInteger, 'integer');

    Report.prototype.expectArray = makeTypeExpectFn(isArray, 'array');

    Report.prototype.expectObject = makeTypeExpectFn(isObject, 'object');

    Report.prototype.expectArrayOrObject = makeMultipleTypesExpectFn([isArray, isObject], ['array', 'object']);

    Report.prototype.expectBooleanOrObject = makeMultipleTypesExpectFn([isBoolean, isObject], ['boolean', 'object']);

    Report.prototype.expectStringOrArray = makeMultipleTypesExpectFn([isString, isArray], ['boolean', 'object']);

    Report.prototype.isValid = function () {
        return this.errors.length === 0;
    };

    Report.prototype.toJSON = function () {
        return {
            valid: this.errors.length === 0,
            errors: this.errors,
            warnings: this.warnings
        };
    };

    Report.prototype.toError = function () {
        var err = new Error('Validation failed');
        err.errors = this.errors;
        err.warnings = this.warnings;
        return err;
    };

    Report.prototype.toPromise = function () {
        if (this.isValid()) {
            return Promise.resolve(this);
        } else {
            return Promise.reject(this.toError());
        }
    };

    Report.prototype.goDown = function (str) {
        this.path.push(str);
    };

    Report.prototype.goUp = function () {
        this.path.pop();
    };

    function validateChild (report, prop, p, val, key) {
        key = (typeof key === 'number') ? '[' + key + ']' : key;
        p = p.then(function () {
            report.path.push(key);
            return validateObject.call(this, report, prop, val)
                .then(function(){
                    report.path.pop()
                });
        }.bind(this));
    }

    function validateChildSync (report, prop, val, key) {
        key = (typeof key === 'number') ? '[' + key + ']' : key;
        report.path.push(key);
        validateObject.call(this, report, prop, val);
        report.path.pop();
    }

    function validateSchemaChildSync (report, prop, key) {
        report.path.push(key);
        _validateSchema.call(this, report, prop);
        report.path.pop();
    }

    function validateSchemaChildrenSync (report, schema, schemaKey) {
        forEach(schema[schemaKey], function (val, key) {
            validateSchemaChildSync.call(this, report, val, schemaKey + '[' + key + ']');
        }.bind(this));
    }

    function validateChildren (report, prop, instance) {
        if (this.options.sync) {
            instance.forEach(validateChildSync.bind(this, report, prop));
            return;
        } else {
            var p = Promise.resolve();
            instance.forEach(function (val, index) {
                report.path.push('[' + index + ']');
                validateObject.call(this, report, prop, val);
                report.path.pop();
            }.bind(this));
            return p;
        }
    }

    function validateChildrenSync (report, prop, instance) {
        instance.forEach(validateChildSync.bind(this, report, prop));
    }

    function validateObject (report, schema, instance) {
        expect.object(schema);

        var thisIsRoot = false;
        if (!report.rootSchema) {
            report.rootSchema = schema;
            thisIsRoot = true;
        }

        var maxRefs = 99;
        while (schema.$ref && maxRefs > 0) {
            if (schema.__$refResolved) {
                schema = schema.__$refResolved;
            } else {
                schema = resolveSchemaQuery(schema, report.rootSchema, schema.$ref, false, this.options.sync, this.schemaCache);
            }
            maxRefs--;
        }

        function step1(val, key) {
            if (InstanceValidators[key] !== undefined) {
                return InstanceValidators[key].call(this, report, schema, instance);
            }
        }

        function step2() {
            // Children calculations
            if (isArray(instance)) {
                return recurseArray.call(this, report, schema, instance);
            } else if (isObject(instance)) {
                return recurseObject.call(this, report, schema, instance);
            }
        }

        function step3() {
            if (thisIsRoot) {
                delete report.rootSchema;
            }
            return report;
        }

        if (this.options.sync) {
            forEach(schema, step1.bind(this));
            step2.call(this);
            step3();
            this._lastError = report.toJSON();
            return report.isValid();
        } else {
            return Promise.all(map(schema, step1.bind(this))).then(step2.bind(this)).then(step3);
        }
    };

    function recurseArray (report, schema, instance) {
        // http://json-schema.org/latest/json-schema-validation.html#rfc.section.8.2

        var p;

        // If items is a schema, then the child instance must be valid against this schema,
        // regardless of its index, and regardless of the value of "additionalItems".
        if (isObject(schema.items)) {
            return validateChildren.call(this, report, schema.items, instance);
        }

        // If "items" is an array, this situation, the schema depends on the index:
        // if the index is less than, or equal to, the size of "items",
        // the child instance must be valid against the corresponding schema in the "items" array;
        // otherwise, it must be valid against the schema defined by "additionalItems".
        if (isArray(schema.items)) {

            if (this.options.sync) {
                instance.forEach(function (val, index) {
                    // equal to doesnt make sense here
                    if (index < schema.items.length) {
                        validateChildSync.call(this, report, schema.items[index], val, index);
                    } else if (isObject(schema.additionalItems)) { // might be boolean
                        validateChildSync.call(this, report, schema.additionalItems, val, index);
                    }
                }, this);
                return;
            } else {
                p = Promise.resolve();
                instance.forEach(function (val, index) {
                    // equal to doesnt make sense here
                    if (index < schema.items.length) {
                        //validateChild.call(this, report, schema.items[index], p, val, index);
                        p = p.then(function () {
                            report.goDown('[' + index + ']');
                            return validateObject.call(this, report, schema.items[index], val)
                                .then(report.goUp.bind(report));
                        }.bind(this));
                    } else if (isObject(schema.additionalItems)) { // might be boolean
                        validateChild.call(this, report, schema.additionalItems, p, val, index);
                    }
                }.bind(this));
                return p;
            }
        }
    };

    function makeInstanceSchemaGetter(schema) {
        // If "additionalProperties" is absent, it is considered present with an empty schema as a value.
        // In addition, boolean value true is considered equivalent to an empty schema.
        var additionalProperties = schema.additionalProperties;
        if (additionalProperties === true || additionalProperties === undefined) {
            additionalProperties = {};
        }
        // p - The property set from "properties".
        var p = Object.keys(schema.properties || {});
        // pp - The property set from "patternProperties". Elements of this set will be called regexes for convenience.
        var pp = Object.keys(schema.patternProperties || {});

        return function(childKey) {
            // s - The set of schemas for the child instance.
            var s = [];

            // 1. If set "p" contains value "childKey", then the corresponding schema in "properties" is added to "s".
            if (p.indexOf(childKey) !== -1) {
                s.push(schema.properties[childKey]);
            }

            // 2. For each regex in "pp", if it matches "childKey" successfully, the corresponding schema in "patternProperties" is added to "s".
            pp.forEach(function (str) {
                if (getRegExp(str).test(childKey) === true) {
                    s.push(schema.patternProperties[str]);
                }
            });

            // 3. The schema defined by "additionalProperties" is added to "s" if and only if, at this stage, "s" is empty.
            if (s.length === 0 && additionalProperties !== false) {
                s.push(additionalProperties);
            }

            // we are passing tests even without this assert because this is covered by properties check
            // if s is empty in this stage, no additionalProperties are allowed
            // report.expect(s.length !== 0, 'E001', childKey);
            return s;
        }
    }

    function recurseObject (report, schema, instance) {
        // http://json-schema.org/latest/json-schema-validation.html#rfc.section.8.3

        var promise = this.options.sync ? null : Promise.resolve();

        var getSchemasForChildInstance = makeInstanceSchemaGetter(schema);

        forEach(instance, function (propertyValue, propertyKey) {
            var s = getSchemasForChildInstance(propertyKey);

            // Instance property value must pass all schemas from s
            s.forEach(function (sch) {
                if (this.options.sync) {
                    validateChildSync.call(this, report, sch, propertyValue, propertyKey);
                } else {
                    //validateChild.call(this, report, sch, promise, propertyValue, propertyKey);
                    promise = promise.then(function () {
                        report.goDown(propertyKey);
                        return validateObject.call(this, report, sch, propertyValue)
                            .then(report.goUp.bind(report));
                    }.bind(this));
                }
            }, this);
        }, this);

        return this.options.sync ? null : promise;
    };

    function validateSchema (report, schema) {
        if (schema.__$validated) {
            return this.options.sync ? schema : Promise.resolve(schema);
        }

        var hasParentSchema = schema.$schema && schema.id !== schema.$schema;

        var finish = function () {
            // run sync validations over schema keywords
            if (this.options.noTypeless === true) {
                report.expect(schema.type !== undefined || schema.anyOf !== undefined || schema.oneOf !== undefined ||
                              schema.not  !== undefined || schema.$ref  !== undefined, 'KEYWORD_UNDEFINED_STRICT', {keyword: 'type'});
            }
            forEach(schema, function (value, key) {
                if (typeof key === 'string' && key.indexOf('__') === 0) {
                    return;
                }
                if (SchemaValidators[key] !== undefined) {
                    SchemaValidators[key].call(this, report, schema);
                } else if (!hasParentSchema) {
                    if (this.options.noExtraKeywords === true) {
                        report.expect(false, 'KEYWORD_UNEXPECTED', {keyword: key});
                    } else {
                        report.addWarning('Unknown key "' + key + '" found in schema.');
                    }
                }
            }.bind(this));
            if (report.isValid()) {
                schema.__$validated = true;
            }
            this._lastError = report.toJSON();
            return this.options.sync ? report.isValid() : report.toPromise();
        };

        // if $schema is present, this schema should validate against that $schema
        if (hasParentSchema) {
            if (this.options.sync) {
                // remote schema will not be validated in sync mode - assume that schema is correct
                return finish.call(this);
            } else {
                var rv = Promise.defer();
                getRemoteSchema(schema.$schema, function (err, remoteSchema) {
                    if (err) {
                        report.addError('SCHEMA_NOT_REACHABLE', {uri: schema.$schema});
                        rv.resolve();
                        return;
                    }
                    // prevent recursion here
                    if (schema.__$downloadedFrom !== remoteSchema.__$downloadedFrom) {
                        validate.call(this, schema, remoteSchema, function (err) {
                            if (err) {
                                report.errors = report.errors.concat(err.errors);
                            }
                            rv.resolve();
                        });
                    } else {
                        rv.resolve();
                    }
                }.bind(this));
                return rv.promise.then(finish.bind(this));
            }
        } else {
            return finish.call(this);
        }
    };

    function validate (json, schema, callback) {
        var report = new Report();

        if (this.options.sync) {
            return validateSync.call(this, json, schema);
        } else {
            // schema compilation is async as some remote requests may occur
            return _compileSchema.call(this, report, schema)
                .then(function (compiledSchema) {
                    // schema validation
                    return _validateSchema.call(this, report, compiledSchema)
                        .then(function () {
                            // object validation against schema
                            return validateObject.call(this, report, compiledSchema, json)
                                .then(function () {
                                    return report.toPromise();
                                });
                        }.bind(this));
                }.bind(this))
                .then(function () {
                    return report.toJSON();
                })
                .nodeify(callback);
        }
    };

    function validateSync (json, schema) {
        var report = new Report();
        if (!schema.__$compiled) {
            _compileSchema.call(this, report, schema);
        }
        if (!schema.__$validated) {
            _validateSchema.call(this, report, schema);
        }
        validateObject.call(this, report, schema, json);
        this._lastError = report.toJSON();
        return report.isValid();
    };

    function _compileSchema (report, schema) {
        // reusing of compiled schemas
        if (schema.__$compiled) {
            return this.options.sync ? schema : Promise.resolve(schema);
        }

        // fix all references
        _fixInnerReferences.call(this, schema);
        _fixOuterReferences(schema);

        // then collect for downloading other schemas
        var refObjs = _collectReferences(schema);
        var refs = uniq(refObjs.map(function (obj) {
            return obj.$ref;
        }));

        function afterDownload() {
            refObjs.forEach(function (refObj) {
                if (!refObj.__$refResolved) {
                    refObj.__$refResolved = resolveSchemaQuery(refObj, schema, refObj.$ref, true, this.options.sync, this.schemaCache) || null;
                }
                if (this.schemaCache && this.schemaCache[refObj.$ref]) {
                    refObj.__$refResolved = this.schemaCache[refObj.$ref];
                }
                report.expect(refObj.__$refResolved != null, 'UNRESOLVABLE_REFERENCE', {ref: refObj.$ref});
            }.bind(this));
            if (report.isValid()) {
                schema.__$compiled = true;
            }
            if (schema.id && this.schemaCache) {
                this.schemaCache[schema.id] = schema;
            }
            return schema;
        }

        function download() {
            return refs.map(function (ref) {
                // never download itself
                if (ref.indexOf(schema.$schema) === 0) {
                    return;
                }
                // download if it is a remote
                if (ref.indexOf('http:') === 0 || ref.indexOf('https:') === 0) {
                    return downloadRemoteReferences.call(this, report, schema, ref.split('#')[0]);
                }
            }.bind(this));
        }

        if (this.options.sync) {
            download.call(this);
            afterDownload.call(this);
        } else {
            return Promise.all(download.call(this)).then(afterDownload.bind(this));
        }
    };

    // recurse schema and collect all references for download
    function _collectReferences (schema) {
        var arr = [];
        if (schema.$ref) {
            arr.push(schema);
        }
        forEach(schema, function (val, key) {
            if (typeof key === 'string' && key.indexOf('__') === 0) {
                return;
            }
            if (isObject(val) || isArray(val)) {
                arr = arr.concat(_collectReferences(val));
            }
        }, this);
        return arr;
    };

    function _fixInnerReferences(rootSchema, schema) {
        if (!schema) {
            schema = rootSchema;
        }
        if (schema.$ref && schema.__$refResolved !== null && schema.$ref.indexOf('http:') !== 0 && schema.$ref.indexOf('https:') !== 0) {
            schema.__$refResolved = resolveSchemaQuery(schema, rootSchema, schema.$ref, true, this.options.sync, this.schemaCache) || null;
        }
        forEach(schema, function (val, key) {
            if (typeof key === 'string' && key.indexOf('__') === 0) {
                return;
            }
            if (isObject(val) || isArray(val)) {
                _fixInnerReferences.call(this, rootSchema, val);
            }
        }, this);
    };

    // fix references according to current scope
    function _fixOuterReferences(schema, scope) {
        scope = scope || [];
        if (isString(schema.id)) {
            scope.push(schema.id);
        }
        if (schema.$ref && !schema.__$refResolved && !isAbsoluteUri(schema.$ref)) {
            if (scope.length > 0) {
                var s = scope.join('').split('#')[0];
                if (schema.$ref[0] === '#') {
                    schema.$ref = s + schema.$ref;
                } else {
                    schema.$ref = s.substring(0, 1 + s.lastIndexOf('/')) + schema.$ref;
                }
            }
        }
        forEach(schema, function (val, key) {
            if (typeof key === 'string' && key.indexOf('__') === 0) {
                return;
            }
            if (isObject(val) || isArray(val)) {
                _fixOuterReferences(val, scope);
            }
        });
        if (isString(schema.id)) {
            scope.pop();
        }
    };

    function _validateSchema (report, schema) {
        if (schema.__$validated) {
            return this.options.sync ? schema : Promise.resolve(schema);
        }

        var hasParentSchema = schema.$schema && schema.id !== schema.$schema;

        var finish = function () {
            // run sync validations over schema keywords
            if (this.options.noTypeless === true) {
                report.expect(schema.type !== undefined || schema.anyOf !== undefined || schema.oneOf !== undefined ||
                              schema.not  !== undefined || schema.$ref  !== undefined, 'KEYWORD_UNDEFINED_STRICT', {keyword: 'type'});
            }
            forEach(schema, function (value, key) {
                if (typeof key === 'string' && key.indexOf('__') === 0) {
                    return;
                }
                if (SchemaValidators[key] !== undefined) {
                    SchemaValidators[key].call(this, report, schema);
                } else if (!hasParentSchema) {
                    if (this.options.noExtraKeywords === true) {
                        report.expect(false, 'KEYWORD_UNEXPECTED', {keyword: key});
                    } else {
                        report.addWarning('Unknown key "' + key + '" found in schema.');
                    }
                }
            }.bind(this));
            if (report.isValid()) {
                schema.__$validated = true;
            }
            this._lastError = report.toJSON();
            return this.options.sync ? report.isValid() : report.toPromise();
        };

        // if $schema is present, this schema should validate against that $schema
        if (hasParentSchema) {
            if (this.options.sync) {
                // remote schema will not be validated in sync mode - assume that schema is correct
                return finish.call(this);
            } else {
                var rv = Promise.defer();
                getRemoteSchema(schema.$schema, function (err, remoteSchema) {
                    if (err) {
                        report.addError('SCHEMA_NOT_REACHABLE', {uri: schema.$schema});
                        rv.resolve();
                        return;
                    }
                    // prevent recursion here
                    if (schema.__$downloadedFrom !== remoteSchema.__$downloadedFrom) {
                        validate.call(this, schema, remoteSchema, function (err) {
                            if (err) {
                                report.errors = report.errors.concat(err.errors);
                            }
                            rv.resolve();
                        });
                    } else {
                        rv.resolve();
                    }
                }.bind(this));
                return rv.promise.then(finish.bind(this));
            }
        } else {
            return finish.call(this);
        }
    };

    // download remote references when needed
    function downloadRemoteReferences (report, rootSchema, uri) {
        if (!rootSchema.__remotes) {
            rootSchema.__remotes = {};
        }

        // do not try to download self
        if (rootSchema.id && uri === rootSchema.id.split('#')[0]) {
            rootSchema.__remotes[uri] = rootSchema;
            return this.options.sync ? null : Promise.resolve();
        }

        if (this.options.sync) {
            // getRemoteSchema is sync when callback is not specified
            var remoteSchema = getRemoteSchema(uri);
            if (remoteSchema) {
                _compileSchema.call(this, report, remoteSchema);
                rootSchema.__remotes[uri] = remoteSchema;
            }
        } else {
            var p = Promise.defer();
            getRemoteSchema(uri, function (err, remoteSchema) {
                if (err) {
                    err.description = 'Connection failed to: ' + uri;
                    return p.reject(err);
                }
                p.resolve(_compileSchema.call(this, report, remoteSchema)
                    .then(function (compiledRemoteSchema) {
                        rootSchema.__remotes[uri] = compiledRemoteSchema;
                    }));
            }.bind(this));
            return p.promise;
        }
    };

    /*
     * Add ability to customize validation later, right now there are no options
     */
    function ZSchema(options) {
        this.options = defaults(options || {}, {
            noExtraKeywords: false, // when on, do not allow unknown keywords in schema
            noZeroLengthStrings: false, // when on, always adds minLength: 1 to schemas where type is string,
            noTypeless: false, // when on, every schema must specify a type
            forceAdditional: false, // when on, forces not to leave out some keys on schemas (additionalProperties, additionalItems)
            forceProperties: false, // when on, forces not to leave out properties or patternProperties on type-object schemas
            forceItems: false, // when on, forces not to leave out items on array-type schemas
            forceMaxLength: false, // when on, forces not to leave out maxLength on string-type schemas, when format or enum is not specified
            noSchemaCache: false, // when on, schema caching is disabled - cache is used to resolve references by id between schemas
            strictUris: false, // when on, strict uris by rfc3986 are required - https://github.com/zaggino/z-schema/issues/18
            sync: false // when on, features that require async handling are disabled - https://github.com/zaggino/z-schema/issues/19
        });
        if (this.options.strict === true) {
            this.options.noExtraKeywords = true;
            this.options.noZeroLengthStrings = true;
            this.options.noTypeless = true;
            this.options.forceAdditional = true;
            this.options.forceProperties = true;
            this.options.forceItems = true;
            this.options.forceMaxLength = true;
        }
        // schema-cache can be turned off for memory / performance gain when not required
        if (this.options.noSchemaCache !== true) {
            this.schemaCache = {};
        }
    }

    // static-methods

    /*
     *  Basic validation entry, uses instance of validator with default options
     */
    ZSchema.validate = function () {
        if (!this._defaultInstance) {
            this._defaultInstance = new ZSchema();
        }
        return this._defaultInstance.validate.apply(this._defaultInstance, arguments);
    };

    /*
     *  Register your own format function to use when validating
     *
     *  `func` can be sync or async and can either return a promise or
     *  execute a classic callback passed as last argument
     */
    ZSchema.registerFormat = function (name, func) {
        expect.string(name);
        expect.callable(func);

        if (FormatValidators[name]) {
            throw new Error('Cannot override built-in validator for ' + name);
        }

        if (CustomFormatValidators[name]) {
            throw new Error('Cannot override existing validator for ' + name);
        }

        CustomFormatValidators[name] = func;
    };

    /**
     * Register your own format validation function and tell ZSchema to call it in sync mode (performance)
     */
    ZSchema.registerFormatSync = function (name, func) {
        func.__$sync = true;
        return ZSchema.registerFormat(name, func);
    };

    /*
     *  Convenience method if you wish to pre-load remote schemas so validator doesn't
     *  have to do that while running validation later.
     */
    ZSchema.setRemoteReference = function (url, data) {
        expect.string(data);
        _getRemoteSchemaCache[url] = data;
    };

    // instance-methods

    /**
     * Validate object against schema
     *
     * @param {Object} json Object to validate
     * @param {Object} schema Schema
     * @param {Function} [callback]
     * @returns {Object} Promise for Report
     */
    ZSchema.prototype.validate = function (json, schema, callback) {
        return validate.apply(this, arguments);
    };

    ZSchema.prototype.validateSync = function(json, schema) {
        return validateSync.apply(this, arguments);
    };

    ZSchema.prototype.getLastError = function () {
        return this._lastError;
    };

    /**
     * Compile Schema
     * @param schema
     * @param {Function} [callback]
     * @returns {Object} Promise for compiled schema
     */
    ZSchema.prototype.compileSchema = function (schema, callback) {

        if (Array.isArray(schema)) {
            return this.options.sync ? this.compileSchemasSync(schema) : this.compileSchemas(schema, callback);
        }

        if (this.options.sync) {
            return this.compileSchemaSync(schema);
        } else {
            var report = new Report();
            return _compileSchema.call(this, report, schema).then(function (compiledSchema) {
                return _validateSchema.call(this, report, compiledSchema).then(function () {
                    return compiledSchema;
                });
            }.bind(this)).nodeify(callback);
        }
    };

    ZSchema.prototype.compileSchemaSync = function (schema) {
        var report = new Report();
        _compileSchema.call(this, report, schema);
        _validateSchema.call(this, report, schema);
        this._lastError = report.toJSON();
        if (report.isValid()) {
            return schema;
        } else {
            throw report.toError();
        }
    }

    /**
     * Compile multiple schemas in one batch
     * @param {Array} array of schemas
     * @param {Function} callback
     * @returns {Object} Promise
     */
    ZSchema.prototype.compileSchemas = function (arr, callback) {
        var compileSchemasFinished = Promise.defer(),
            compiled = [],
            failed = [],
            lastError;

        var loopArrayFinished;
        function loopArray() {
            // condition
            if (arr.length === 0) { return loopArrayFinished.resolve(); }
            // body
            var nextSchema = arr.shift();
            this.compileSchema(nextSchema).then(function () {
                compiled.push(nextSchema);
            }).catch(function (err) {
                lastError = err;
                failed.push(nextSchema);
            }).finally(loopArray.bind(this));
        }

        var lastArrayLength;
        function loopCompile() {
            // condition
            if (arr.length === 0) { return compileSchemasFinished.resolve(compiled); }
            if (arr.length === lastArrayLength) { return compileSchemasFinished.reject(lastError); }
            // body
            lastArrayLength = arr.length;
            loopArrayFinished = Promise.defer();
            loopArrayFinished.promise.then(function () {
                arr = failed;
                failed = [];
                loopCompile.call(this);
            }.bind(this));
            loopArray.call(this);
        }
        loopCompile.call(this);

        return compileSchemasFinished.promise.nodeify(callback);
    };

    ZSchema.prototype.compileSchemasSync = function (arr) {
        var lastError,
            compiled,
            retArr = [];

        function cycle() {
            compiled = 0;
            arr.forEach(function (sch, i) {
                try {
                    this.compileSchema(sch);
                } catch (e) {
                    lastError = e;
                    return;
                }
                compiled++;
                retArr.push(sch);
                arr.splice(i, 1);
            }.bind(this));
        }

        do {
            cycle.call(this);
        } while (compiled > 0);

        if (arr.length === 0) {
            return retArr;
        } else {
            throw lastError;
        }
    };

    /**
     * Validate schema
     *
     * @param schema
     * @param {Function} callback
     * @returns {Object} Promise for Report
     */
    ZSchema.prototype.validateSchema = function (schema, callback) {
        var report = new Report();
        report.expect(isObject(schema), 'SCHEMA_TYPE_EXPECTED');

        if (this.options.sync) {
            return this.validateSchemaSync(schema);
        } else {
            return _validateSchema.call(this, report, schema)
                .then(function () {
                    return report.toJSON();
                })
                .nodeify(callback);
        }
    };

    ZSchema.prototype.validateSchemaSync = function (schema) {
        var report = new Report();
        report.expect(isObject(schema), 'SCHEMA_TYPE_EXPECTED');
        _validateSchema.call(this, report, schema);
        this._lastError = report.toJSON();
        if (report.isValid()) {
            return schema;
        } else {
            throw report.toError();
        }
    };

    /*
     * use this functions to validate json schema itself
     * every code here SHOULD reference json schema specification
     */

    var SchemaValidators = {};

    // http://tools.ietf.org/html/draft-ietf-appsawg-json-pointer-07
    // http://tools.ietf.org/html/draft-pbryan-zyp-json-ref-03
    SchemaValidators.$ref = function (report, schema) {
        report.expectString(schema.$ref, '$ref');
    };

    // http://json-schema.org/latest/json-schema-core.html#rfc.section.6
    SchemaValidators.$schema = function (report, schema) {
        report.expectString(schema.$schema, '$schema');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.1.1
    SchemaValidators.multipleOf = function (report, schema) {
        var fine = report.expectNumber(schema.multipleOf, 'multipleOf');
        if (!fine) { return; }
        report.expect(schema.multipleOf > 0, 'KEYWORD_MUST_BE', { keyword: 'multipleOf', expression: 'strictly greater than 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.2.1
    SchemaValidators.maximum = function (report, schema) {
        report.expectNumber(schema.maximum, 'maximum');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.2.1
    SchemaValidators.exclusiveMaximum = function (report, schema) {
        var fine = report.expectBoolean(schema.exclusiveMaximum, 'exclusiveMaximum');
        if (!fine) { return; }
        report.expect(schema.maximum !== undefined, 'KEYWORD_DEPENDENCY', {keyword1: 'exclusiveMaximum', keyword2: 'maximum'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.3.1
    SchemaValidators.minimum = function (report, schema) {
        report.expectNumber(schema.minimum, 'minimum');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.3.1
    SchemaValidators.exclusiveMinimum = function (report, schema) {
        var fine = report.expectBoolean(schema.exclusiveMinimum, 'exclusiveMinimum');
        if (!fine) { return; }
        report.expect(schema.minimum !== undefined, 'KEYWORD_DEPENDENCY', {keyword1: 'exclusiveMinimum', keyword2: 'minimum'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.2.1.1
    SchemaValidators.maxLength = function (report, schema) {
        var fine = report.expectInteger(schema.maxLength, 'maxLength');
        if (!fine) { return; }
        report.expect(schema.maxLength >= 0, 'KEYWORD_MUST_BE', {keyword: 'maxLength', expression: 'greater than, or equal to 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.2.2.1
    SchemaValidators.minLength = function (report, schema) {
        var fine = report.expectInteger(schema.minLength, 'minLength');
        if (!fine) { return; }
        report.expect(schema.minLength >= 0, 'KEYWORD_MUST_BE', {keyword: 'minLength', expression: 'greater than, or equal to 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.2.3.1
    SchemaValidators.pattern = function (report, schema) {
        var fine = report.expectString(schema.pattern, 'pattern');
        if (!fine) { return; }
        try {
            getRegExp(schema.pattern);
        } catch (e) {
            report.addError('KEYWORD_PATTERN', {keyword: 'pattern', pattern: schema.pattern});
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.1.1
    SchemaValidators.additionalItems = function (report, schema) {
        var fine = report.expectBooleanOrObject(schema.additionalItems, 'additionalItems');
        if (!fine) { return; }
        if (isObject(schema.additionalItems)) {
            validateSchemaChildSync.call(this, report, schema.additionalItems, 'additionalItems');
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.1.1
    SchemaValidators.items = function (report, schema) {
        var fine = report.expectArrayOrObject(schema.items, 'items');
        if (!fine) { return; }
        if (isObject(schema.items)) {
            validateSchemaChildSync.call(this, report, schema.items, 'items');
        } else if (isArray(schema.items)) {
            validateSchemaChildrenSync.call(this, report, schema, 'items');
        }
        // custom - strict mode
        if (this.options.forceAdditional === true) {
            report.expect(schema.additionalItems !== undefined, 'KEYWORD_UNDEFINED_STRICT', {keyword: 'additionalItems'});
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.2.1
    SchemaValidators.maxItems = function (report, schema) {
        var fine = report.expectInteger(schema.maxItems, 'maxItems');
        if (!fine) { return; }
        report.expect(schema.maxItems >= 0, 'KEYWORD_MUST_BE', {keyword: 'maxItems', expression: 'greater than, or equal to 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.3.1
    SchemaValidators.minItems = function (report, schema) {
        var fine = report.expectInteger(schema.minItems, 'minItems');
        if (!fine) { return; }
        report.expect(schema.minItems >= 0, 'KEYWORD_MUST_BE', {keyword: 'minItems', expression: 'greater than, or equal to 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.4.1
    SchemaValidators.uniqueItems = function (report, schema) {
        report.expectBoolean(schema.uniqueItems, 'uniqueItems');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.1.1
    SchemaValidators.maxProperties = function (report, schema) {
        var fine = report.expectInteger(schema.maxProperties, 'maxProperties');
        if (!fine) { return; }
        report.expect(schema.maxProperties >= 0, 'KEYWORD_MUST_BE', {keyword: 'maxProperties', expression: 'greater than, or equal to 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.2.1
    SchemaValidators.minProperties = function (report, schema) {
        var fine = report.expectInteger(schema.minProperties, 'minProperties');
        if (!fine) { return; }
        report.expect(schema.minProperties >= 0, 'KEYWORD_MUST_BE', {keyword: 'minProperties', expression: 'greater than, or equal to 0'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.3.1
    SchemaValidators.required = function (report, schema) {
        var fine = report.expectArray(schema.required, 'required');
        if (!fine) { return; }
        fine = report.expect(schema.required.length > 0,
                             'KEYWORD_MUST_BE', {keyword: 'required', expression: 'an array with at least one element'});
        if (!fine) { return; }
        schema.required.forEach(function (el) {
            report.expect(isString(el), 'KEYWORD_VALUE_TYPE', {keyword: 'required', type: 'string'});
        }, this);
        report.expect(isUniqueArray(schema.required), 'KEYWORD_MUST_BE', {keyword: 'required', expression: 'an array with unique items'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.4.1
    SchemaValidators.additionalProperties = function (report, schema) {
        var fine = report.expectBooleanOrObject(schema.additionalProperties, 'additionalProperties');
        if (!fine) { return; }
        if (isObject(schema.additionalProperties)) {
            validateSchemaChildSync.call(this, report, schema.additionalProperties, 'additionalProperties');
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.4.1
    SchemaValidators.properties = function (report, schema) {
        var fine = report.expectObject(schema.properties, 'properties');
        if (!fine) { return; }
        validateSchemaChildrenSync.call(this, report, schema, 'properties');

        // custom - strict mode
        if (this.options.forceAdditional === true) {
            report.expect(schema.additionalProperties !== undefined, 'KEYWORD_UNDEFINED_STRICT', {keyword: 'additionalProperties'});
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.4.1
    SchemaValidators.patternProperties = function (report, schema) {
        var fine = report.expectObject(schema.patternProperties, 'patternProperties');
        if (!fine) { return; }
        forEach(schema.patternProperties, function (val, propName) {
            try {
                getRegExp(propName);
            } catch (e) {
                report.addError('KEYWORD_PATTERN', {keyword: 'patternProperties', pattern: propName});
            }
            validateSchemaChildSync.call(this, report, val, 'patternProperties[' + propName + ']');
        }.bind(this));
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.5.1
    SchemaValidators.dependencies = function (report, schema) {
        var fine = report.expectObject(schema.dependencies, 'dependencies');
        if (!fine) { return; }
        forEach(schema.dependencies, function (schemaDependency, schemaKey) {
            report.expectArrayOrObject(schemaDependency, 'dependencies');
            if (isObject(schemaDependency)) {
                validateSchemaChildSync.call(this, report, schemaDependency, 'dependencies[' + schemaKey + ']');
            } else if (isArray(schemaDependency)) {
                report.expect(schemaDependency.length > 0, 'KEYWORD_MUST_BE', {keyword: 'dependencies', expression: 'not empty array'});
                schemaDependency.forEach(function (el) {
                    report.expect(isString(el), 'KEYWORD_VALUE_TYPE', {keyword: 'dependencies', type: 'string'});
                });
                report.expect(isUniqueArray(schemaDependency), {keyword: 'dependencies', expression: 'an array with unique items'});
            }
        }.bind(this));
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.1.1
    SchemaValidators.enum = function (report, schema) {
        var fine = report.expectArray(schema.enum, 'enum');
        if (!fine) { return; }
        fine = report.expect(schema.enum.length > 0, 'KEYWORD_MUST_BE', {keyword: 'enum', expression: 'an array with at least one element'});
        if (!fine) { return; }
        fine = report.expect(isUniqueArray(schema.enum), 'KEYWORD_MUST_BE', {keyword: 'enum', expression: 'an array with unique items'});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.2.1
    SchemaValidators.type = function (report, schema) {
        var primitiveTypes = ['array', 'boolean', 'integer', 'number', 'null', 'object', 'string'];
        var primitiveTypeStr = primitiveTypes.join(',');
        var fine = report.expectStringOrArray(schema.type, 'type');
        if (!fine) { return; }
        var isArray = Array.isArray(schema.type);
        if (isArray) {
            schema.type.forEach(function (el) {
                report.expect(primitiveTypes.indexOf(el) !== -1, 'KEYWORD_TYPE_EXPECTED', { keyword: 'type', type: primitiveTypeStr});
            }, this);
            report.expect(isUniqueArray(schema.type), 'KEYWORD_MUST_BE', {keyword: 'type', expression: 'an object with unique properties'});
        } else {
            report.expect(primitiveTypes.indexOf(schema.type) !== -1, 'KEYWORD_TYPE_EXPECTED', { keyword: 'type', type: primitiveTypeStr});
        }
        if (this.options.noZeroLengthStrings === true) {
            if (schema.type === 'string' || isArray && schema.type.indexOf('string') !== -1) {
                if (schema.minLength === undefined) {
                    schema.minLength = 1;
                }
            }
        }
        if (this.options.forceProperties === true) {
            if (schema.type === 'object' || isArray && schema.type.indexOf('object') !== -1) {
                report.expect(schema.properties !== undefined || schema.patternProperties !== undefined,
                              'KEYWORD_UNDEFINED_STRICT', {keyword: 'properties'});
            }
        }
        if (this.options.forceItems === true) {
            if (schema.type === 'array' || isArray && schema.type.indexOf('array') !== -1) {
                report.expect(schema.items !== undefined, 'KEYWORD_UNDEFINED_STRICT', {keyword: 'items'});
            }
        }
        if (this.options.forceMaxLength === true) {
            if (schema.type === 'string' || isArray && schema.type.indexOf('string') !== -1) {
                report.expect(schema.maxLength !== undefined || schema.format !== undefined || schema.enum !== undefined,
                              'KEYWORD_UNDEFINED_STRICT', {keyword: 'maxLength'});
            }
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.3.1
    SchemaValidators.allOf = function (report, schema) {
        var fine = report.expectArray(schema.allOf, 'allOf');
        if (!fine) { return; }
        fine = report.expect(schema.allOf.length > 0, 'KEYWORD_MUST_BE', {keyword: 'allOf', expression: 'an array with at least one element'});
        if (!fine) { return; }
        validateSchemaChildrenSync.call(this, report, schema, 'allOf');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.4.1
    SchemaValidators.anyOf = function (report, schema) {
        var fine = report.expectArray(schema.anyOf, 'anyOf');
        if (!fine) { return; }
        fine = report.expect(schema.anyOf.length > 0, 'KEYWORD_MUST_BE', {keyword: 'anyOf', expression: 'an array with at least one element'});
        if (!fine) { return; }
        validateSchemaChildrenSync.call(this, report, schema, 'anyOf');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.5.1
    SchemaValidators.oneOf = function (report, schema) {
        var fine = report.expectArray(schema.oneOf, 'oneOf');
        if (!fine) { return; }
        fine = report.expect(schema.oneOf.length > 0, 'KEYWORD_MUST_BE', {keyword: 'oneOf', expression: 'an array with at least one element'});
        if (!fine) { return; }
        validateSchemaChildrenSync.call(this, report, schema, 'oneOf');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.6.1
    SchemaValidators.not = function (report, schema) {
        var fine = report.expectObject(schema.not, 'not');
        if (!fine) { return; }
        validateSchemaChildSync.call(this, report, schema.not, 'not');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.7.1
    SchemaValidators.definitions = function (report, schema) {
        var fine = report.expectObject(schema.definitions, 'definitions');
        if (!fine) { return; }
        validateSchemaChildrenSync.call(this, report, schema, 'definitions');
    };

    SchemaValidators.format = function (report, schema) {
        var fine = report.expectString(schema.format, 'format');
        if (!fine) { return; }
        fine = report.expect(isFunction(FormatValidators[schema.format]) || isFunction(CustomFormatValidators[schema.format]),
                             'UNKNOWN_FORMAT', {format: schema.format});
        if (!fine) { return; }
    };

    // http://json-schema.org/latest/json-schema-core.html#rfc.section.7.2
    SchemaValidators.id = function (report, schema) {
        report.expectString(schema.id, 'id');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.6.1
    SchemaValidators.title = function (report, schema) {
        report.expectString(schema.title, 'title');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.6.1
    SchemaValidators.description = function (report, schema) {
        report.expectString(schema.description, 'description');
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.6.2
    SchemaValidators.default = noop;

    // ---- custom key used by ZSchema
    SchemaValidators.__$compiled = function (report, schema) {
        expect.boolean(schema.__$compiled);
    };

    // ---- custom key used by ZSchema
    SchemaValidators.__$validated = function (report, schema) {
        expect.boolean(schema.__$validated);
    };

    function validateOnlyIf(pred, validationFn) {
        return function(report, schema, instance) {
            if (!pred(instance)) {
                return;
            }
            validationFn.apply(this, arguments);
        }
    }

    var InstanceValidators = {};

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.1.2
    InstanceValidators.multipleOf = validateOnlyIf(isNumber, function (report, schema, instance) {
        var isInteger = whatIs(instance / schema.multipleOf) === 'integer';
        report.expect(isInteger,
            'MULTIPLE_OF',
            { value: instance, multipleOf: schema.multipleOf}
        );
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.2.2
    InstanceValidators.maximum = validateOnlyIf(isNumber, function (report, schema, instance) {
        if (schema.exclusiveMaximum !== true) {
            report.expect(instance <= schema.maximum,
                'MAXIMUM',
                { value: instance, maximum: schema.maximum}
            );
        } else {
            report.expect(instance < schema.maximum,
                'MAXIMUM_EXCLUSIVE',
                { value: instance, maximum: schema.maximum}
            );
        }
    });

    // covered in maximum
    InstanceValidators.exclusiveMaximum = noop;

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.1.3.2
    InstanceValidators.minimum = validateOnlyIf(isNumber, function (report, schema, instance) {
        if (schema.exclusiveMinimum !== true) {
            report.expect(instance >= schema.minimum,
                'MINIMUM',
                { value: instance, minimum: schema.minimum}
            );
        } else {
            report.expect(instance > schema.minimum,
                'MINIMUM_EXCLUSIVE',
                { value: instance, minimum: schema.minimum}
            );
        }
    });

    // covered in minimum
    InstanceValidators.exclusiveMinimum = noop;

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.2.1.2
    InstanceValidators.maxLength = validateOnlyIf(isString, function (report, schema, instance) {
        report.expect(instance.length <= schema.maxLength,
            'MAX_LENGTH',
            { length: instance.length, maximum: schema.maxLength}
        );
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.2.2.2
    InstanceValidators.minLength = validateOnlyIf(isString, function (report, schema, instance) {
        report.expect(instance.length >= schema.minLength,
            'MIN_LENGTH',
            { length: instance.length, minimum: schema.minLength}
        );
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.2.3.2
    InstanceValidators.pattern = validateOnlyIf(isString, function (report, schema, instance) {
        report.expect(getRegExp(schema.pattern).test(instance),
            'PATTERN',
            { pattern: schema.pattern});
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.1.2
    InstanceValidators.additionalItems = validateOnlyIf(isArray, function (report, schema, instance) {
        // if the value of "additionalItems" is boolean value false and the value of "items" is an array,
        // the instance is valid if its size is less than, or equal to, the size of "items".
        if (schema.additionalItems === false && isArray(schema.items)) {
            report.expect(instance.length <= schema.items.length, 'ARRAY_ADDITIONAL_ITEMS');
        }
    });

    // covered in additionalItems
    InstanceValidators.items = noop;

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.2.2
    InstanceValidators.maxItems = validateOnlyIf(isArray, function (report, schema, instance) {
        report.expect(instance.length <= schema.maxItems, 'ARRAY_LENGTH_LONG', {length: instance.length, maximum: schema.maxItems});
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.3.2
    InstanceValidators.minItems = validateOnlyIf(isArray, function (report, schema, instance) {
        report.expect(instance.length >= schema.minItems, 'ARRAY_LENGTH_SHORT', {length: instance.length, minimum: schema.minItems});
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.3.4.2
    InstanceValidators.uniqueItems = validateOnlyIf(isArray, function (report, schema, instance) {
        if (schema.uniqueItems === true) {
            var matches = {};
            report.expect(isUniqueArray(instance, matches), 'ARRAY_UNIQUE', matches);
        }
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.1.2
    InstanceValidators.maxProperties = validateOnlyIf(isObject, function (report, schema, instance) {
        var keysCount = Object.keys(instance).length;
        report.expect(keysCount <= schema.maxProperties, 'OBJECT_PROPERTIES_MAXIMUM', {count: keysCount, maximum: schema.maxProperties});
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.2.2
    InstanceValidators.minProperties = validateOnlyIf(isObject, function (report, schema, instance) {
        var keysCount = Object.keys(instance).length;
        report.expect(keysCount >= schema.minProperties, 'OBJECT_PROPERTIES_MINIMUM', {count: keysCount, minimum: schema.minProperties});
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.3.2
    InstanceValidators.required = validateOnlyIf(isObject, function (report, schema, instance) {
        schema.required.forEach(function (reqProperty) {
            report.expect(instance[reqProperty] !== undefined, 'OBJECT_REQUIRED', {property: reqProperty});
        });
    });

    InstanceValidators.additionalProperties = function (report, schema) { /*instance*/
        // covered in properties and patternProperties
        if (schema.properties === undefined && schema.patternProperties === undefined) {
            return InstanceValidators.properties.apply(this, arguments);
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.4.2
    InstanceValidators.properties = validateOnlyIf(isObject, function (report, schema, instance) {
        var properties = schema.properties !== undefined ? schema.properties : {};
        var patternProperties = schema.patternProperties !== undefined ? schema.patternProperties : {};
        if (schema.additionalProperties === false) {
            // The property set of the instance to validate.
            var s = Object.keys(instance);
            // The property set from "properties".
            var p = Object.keys(properties);
            // The property set from "patternProperties".
            var pp = Object.keys(patternProperties);
            // remove from "s" all elements of "p", if any;
            s = difference(s, p);
            // for each regex in "pp", remove all elements of "s" which this regex matches.
            pp.forEach(function (patternProperty) {
                var regExp = getRegExp(patternProperty);
                for (var i = s.length - 1; i >= 0; i--) {
                    if (regExp.test(s[i]) === true) {
                        s.splice(i, 1);
                    }
                }
            });
            // Validation of the instance succeeds if, after these two steps, set "s" is empty.
            report.expect(s.length === 0, 'OBJECT_ADDITIONAL_PROPERTIES', {properties: s});
        }
    });

    InstanceValidators.patternProperties = function (report, schema) { /*instance*/
        // covered in properties
        if (schema.properties === undefined) {
            return InstanceValidators.properties.apply(this, arguments);
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.4.5.2
    InstanceValidators.dependencies = validateOnlyIf(isObject, function (report, schema, instance) {
        var promiseArray = [];

        forEach(schema.dependencies, function (dependency, name) {
            if (instance[name] !== undefined) {
                if (isObject(dependency)) {
                    // errors will be added to same report
                    promiseArray.push(validateObject.call(this, report, dependency, instance));
                } else { // Array
                    forEach(dependency, function (requiredProp) {
                        report.expect(instance[requiredProp] !== undefined, 'OBJECT_DEPENDENCY_KEY', { missing: requiredProp, key: name });
                    });
                }
            }
        }, this);

        return this.options.sync ? null : Promise.all(promiseArray);
    });

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.1.2
    InstanceValidators.enum = function (report, schema, instance) {
        var match = false;
        for (var i = 0, l = schema.enum.length; i < l; i++) {
            if (deepEqual(instance, schema.enum[i])) {
                match = true;
                break;
            }
        }
        report.expect(match, 'ENUM_MISMATCH', {value: instance});
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.2.2
    InstanceValidators.type = function (report, schema, instance) {
        var instanceType = whatIs(instance);
        if (isString(schema.type)) {
            report.expect(instanceType === schema.type || instanceType === 'integer' && schema.type === 'number',
                'INVALID_TYPE', { expected: schema.type, type: instanceType});
        } else {
            var one = schema.type.indexOf(instanceType) !== -1;
            var two = instanceType === 'integer' && schema.type.indexOf('number') !== -1;
            report.expect(one || two, 'INVALID_TYPE', { expected: schema.type, type: instanceType});
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.3.2
    InstanceValidators.allOf = function (report, schema, instance) {
        if (this.options.sync) {
            var i = schema.allOf.length;
            while (i--) {
                // validateObject returns isValid boolean
                if (!validateObject.call(this, report, schema.allOf[i], instance)) { break; }
            }
        } else {
            return Promise.all(schema.allOf.map(function (sch) {
                return validateObject.call(this, report, sch, instance);
            }.bind(this)));
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.4.2
    InstanceValidators.anyOf = function (report, schema, instance) {
        var subReports = [];
        if (this.options.sync) {
            var passed = false,
                i = schema.anyOf.length;
            while (i-- && !passed) {
                var subReport = new Report(report);
                subReports.push(subReport);
                passed = validateObject.call(this, subReport, schema.anyOf[i], instance);
            }
            report.expect(passed, 'ANY_OF_MISSING', {}, subReports);
            return;
        } else {
            var passes = 0,
                p = Promise.resolve();
            schema.anyOf.forEach(function (anyOf) {
                p = p.then(function () {
                    if (passes > 0) { return; }
                    var subReport = new Report(report);
                    return validateObject.call(this, subReport, anyOf, instance)
                        .then(function () {
                            if (subReport.isValid()) {
                                passes++;
                            } else {
                                subReports.push(subReport);
                            }
                        });
                }.bind(this));
            }.bind(this));
            return p.then(function () {
                report.expect(passes >= 1, 'ANY_OF_MISSING', {}, passes === 0 ? subReports : null);
            });
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.5.2
    InstanceValidators.oneOf = function (report, schema, instance) {
        var passes = 0;
        var subReports = [];

        function finish() {
            report.expect(passes > 0, 'ONE_OF_MISSING', {}, passes === 0 ? subReports : null);
            report.expect(passes < 2, 'ONE_OF_MULTIPLE');
        }

        if (this.options.sync) {
            var i = schema.oneOf.length;
            while (i--) {
                var subReport = new Report(report);
                subReports.push(subReport);
                if (validateObject.call(this, subReport, schema.oneOf[i], instance)) {
                    passes++;
                }
            }
            return finish();
        } else {
            return Promise.all(schema.oneOf.map(function (oneOf) {
                var subReport = new Report(report);
                return validateObject.call(this, subReport, oneOf, instance)
                    .then(function () {
                        if (subReport.isValid()) {
                            passes++;
                        } else {
                            subReports.push(subReport);
                        }
                    });
            }.bind(this))).then(finish);
        }
    };

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.6.2
    InstanceValidators.not = function (report, schema, instance) {
        var subReport = new Report(report);

        function finish() {
            report.expect(!subReport.isValid(), 'NOT_PASSED');
        }

        if (this.options.sync) {
            validateObject.call(this, subReport, schema.not, instance);
            finish();
        } else {
            return validateObject.call(this, subReport, schema.not, instance).then(finish);
        }
    };

    //http://json-schema.org/latest/json-schema-validation.html#rfc.section.5.5.7.2
    InstanceValidators.definitions = noop;

    // http://json-schema.org/latest/json-schema-validation.html#rfc.section.7.2
    InstanceValidators.format = function (report, schema, instance) {
        var p;

        if (typeof FormatValidators[schema.format] === 'function') { // built-in format (sync)
            report.expect(FormatValidators[schema.format](instance, this), 'FORMAT', {format: schema.format, error: instance});
            return;
        }

        // custom format was registered as sync function, so we can do some speedup
        if (CustomFormatValidators[schema.format].__$sync === true) {
            try {
                p = CustomFormatValidators[schema.format](instance);
                if (p !== true) {
                    report.addError('FORMAT', {format: schema.format});
                }
            } catch (err) {
                report.addError('FORMAT', {format: schema.format, error: err});
            }

            return;
        }

        // custom format (sync or async)
        var deferred = Promise.defer();

        try {
            p = CustomFormatValidators[schema.format](instance, deferred.callback);
            if (Promise.is(p) || isBoolean(p)) {
                deferred.resolve(p);
            }
        } catch (e) {
            deferred.reject(e);
        }

        return deferred.promise
            .then(function (valid) { // validators may return (resolve with) true/false
                if (!valid) {
                    report.addError('FORMAT', {format: schema.format});
                }
            })
            .catch(function (err) { // validators may throw Error or return rejected promise
                report.addError('FORMAT', {format: schema.format, error: err});
            });
    };

    module.exports = ZSchema;

}());
