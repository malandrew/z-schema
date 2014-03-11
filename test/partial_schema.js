/*jshint strict:false, loopfunc:true*/
/*global describe, it*/

var ZSchema = require("../src/ZSchema");
var assert = require("chai").assert;

describe("resolveSchemaQuery fallback to schemaCache", function () {

    it("should validate against a cached schema definition", function (done) {

        var schema = {
            "$schema": "http://json-schema.org/schema#",
            "id": "lib://test-schema",
            "$ref": "lib://test-schema#/definitions/person-object",
            "definitions": {
                "email": {
                    "type": "string",
                    "pattern": "^([0-9a-zA-Z]([-\\.\\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\\w]*[0-9a-zA-Z]\\.)+[a-zA-Z]{2,9})$"
                },
                "uri-http": {
                    "type": "string",
                    "pattern": "^https?:\/\/"
                },
                "person-object": {
                    "type": "object",
                    "required": [
                        "name"
                    ],
                    "properties": {
                        "name": {
                            "type": "string",
                            "pattern": "[a-zA-Z]"
                        },
                        "email": {
                            "$ref": "lib://test-schema#/definitions/email"
                        },
                        "url": {
                            "$ref": "lib://test-schema#/definitions/uri-http"
                        }
                    }
                }
            }
        };
        

        var validator = new ZSchema();
        validator.compileSchema(schema, function (err, compiledSchema) {

            var contributors = require("../package.json").contributors;
            var subSchema = compiledSchema.definitions["person-object"];

            validator.validate(contributors[0], subSchema, function (err, report) {
                try {
                    assert.isNull(err);
                    assert.isTrue(report.valid);
                } catch (e) {
                    return done(e);
                }
                done();
            });

        });

    });

});
