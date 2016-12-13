'use strict';

const AzureOAuth2Strategy = require('passport-azure-oauth2');
const passport = require('passport');
const refresh = require('passport-oauth2-refresh');

class Office365Strategy extends AzureOAuth2Strategy {
    constructor(options, verify) {
        super(Object.assign({
            resource: 'https://api.office.com/discovery/',
            passReqToCallback: true
        }, options), (req, accessToken, refreshToken, params, profile, done) => {
            this.discoverServices(accessToken, options.discoverUrl || 'https://api.office.com/discovery/v1.0/me/Services')
                .then(services => {
                    return Promise.all(services.map(s => {
                        return this.getAccessToService(refreshToken, s);
                    }));
                })
                .then(results => {
                        const arity = verify.length;
                        if (options.passReqToCallback) {
                            if (arity === 6) {
                                verify(req, results, refreshToken, params, profile, done);
                            } else {
                                verify(req, results, refreshToken, profile, done);
                            }
                        } else {
                            if (arity === 5) {
                                verify(results, refreshToken, params, profile, done);
                            } else {
                                verify(results, refreshToken, profile, done);
                            }
                        }
                    },
                    error => {
                        done(null, false, error.info);
                    });
        });
    }

    discoverServices(accessToken, discoverUrl = ) {
        return new Promise((resolve, reject) => {
            this._oauth2.get(discoverUrl, accessToken, (err, body) =>{
                if (err) {
                    reject({err});
                } else {
                    try {
                        const json = JSON.parse(body);
                        resolve(json.value);
                    } catch (ex) {
                        reject(new Error('Failed to parse services'));
                    }
                }
            });
        });
    }

    getAccessToService(refreshToken, service) {
        return new Promise((resolve, reject) => {
            const name = this.getStrategyName();
            refresh.requestNewAccessToken(name, refreshToken, {
                resource: service.serviceResourceId
            }, (err, accessToken, refreshToken) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(Object.assign({accessToken, refreshToken}, service));
                }
            });
        });
    }

    getStrategyName() {
        for (let name of Object.getOwnPropertyNames(refresh._strategies)) {
            if (refresh._strategies[name].strategy === this) {
                return name;
            }
        }
    }
}

module.exports = Office365Strategy;