'use strict';

const AzureOAuth2Strategy = require('passport-azure-oauth2'),
    passport = require('passport'),
    refresh = require('passport-oauth2-refresh');

function getAccessToService(refreshToken, service) {
    return new Promise((resolve, reject) => {
        refresh.requestNewAccessToken(service.capability, refreshToken, {
            resource: service.serviceResourceId
        }, (err, accessToken, refreshToken) => {
            if (err) {
                reject(err);
            } else {
                resolve({accessToken, refreshToken});
            }
        });
    });
}

function wrapVerify(req, accessToken, refreshToken, params, profile, origVerify, passReqToCallback) {
    return new Promise((resolve, reject) => {
        const verify = (err, user, info) => {
                if (err) {
                    reject({err});
                } else if (!user) {
                    reject({info});
                } else {
                    resolve(user);
                }
            },
            arity = origVerify.length;
        if (passReqToCallback) {
            if (arity === 6) {
                origVerify(req, accessToken, refreshToken, params, profile, verify);
            } else {
                origVerify(req, accessToken, refreshToken, profile, verify);
            }
        } else {
            if (arity === 5) {
                origVerify(accessToken, refreshToken, params, profile, verify);
            } else {
                origVerify(accessToken, refreshToken, profile, verify);
            }
        }
    });
}

class Office365Strategy extends AzureOAuth2Strategy {
    constructor(options, verify) {
        super(Object.assign({
            resource: "https://api.office.com/discovery/",
            passReqToCallback: true
        }, options), (req, accessToken, refreshToken, params, profile, done) => {
            this.discoverServices(accessToken)
                .then(services => {
                    return Promise.all(services.map(s => {
                        getAccessToService(refreshToken, s)
                            .then(result => wrapVerify(req, result.accessToken, result.refreshToken, s, profile, verify, options.passReqToCallback));
                    }));
                })
                .then(() => done(null, profile))
                .catch(error => {
                    if (error.err) {
                        done(error.err);
                    } else {
                        done(null, false, error.info);
                    }
                });
        });
    }

    discoverServices(accessToken) {
        return new Promise((resolve, reject) => {
            this._oauth2.get('https://api.office.com/discovery/v1.0/me/Services', accessToken, function (err, body) {
                if (err) {
                    reject({err});
                } else {
                    try {
                        let json = JSON.parse(body);
                        resolve(json);
                    } catch (ex) {
                        reject(new Error('Failed to parse user profile'));
                    }
                }
            });
        });
    }
}

module.exports = Office365Strategy;