'use strict';

const AzureOAuth2Strategy = require('passport-azure-oauth2'),
    fetch = require('node-fetch'),
    passport = require('passport'),
    refresh = require('passport-oauth2-refresh');

function discoverServices(accessToken) {
    return fetch('https://api.office.com/discovery/v1.0/me/Services', {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    })
        .then(response => response.json());
}

function createServiceStrategy(service, options) {
    let serviceStrategy = new AzureOAuth2Strategy(Object.assign({}, options, {
        resource: service.serviceResourceId
    }), (accessToken, refreshToken, profile, done) => {
        done(null, profile);
    });
    serviceStrategy._oauth2.useAuthorizationHeaderforGET(true);
    passport.use(service.capability, serviceStrategy);
    refresh.use(service.capability, serviceStrategy);
}

function refreshServiceTokens(refreshToken, service) {
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

function getAccessToService(refreshToken, service, options) {
    createServiceStrategy(service, options);
    return refreshServiceTokens(refreshToken, service);
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

class Office365 extends AzureOAuth2Strategy {
    constructor(options, verify) {
        super(Object.assign({
            resource: "https://api.office.com/discovery/",
            passReqToCallback: true
        }, options), (req, accessToken, refreshToken, params, profile, done) => {
            discoverServices
                .then(services => {
                    return Promise.all(services.map(s => {
                        getAccessToService(refreshToken, s, options)
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
}

module.exports = Office365;