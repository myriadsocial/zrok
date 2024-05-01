/* tslint:disable */
/* eslint-disable */
/**
 * zrok
 * zrok client access
 *
 * The version of the OpenAPI document: 0.3.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface Frontend
 */
export interface Frontend {
    /**
     * 
     * @type {number}
     * @memberof Frontend
     */
    id?: number;
    /**
     * 
     * @type {string}
     * @memberof Frontend
     */
    shrToken?: string;
    /**
     * 
     * @type {string}
     * @memberof Frontend
     */
    zId?: string;
    /**
     * 
     * @type {number}
     * @memberof Frontend
     */
    createdAt?: number;
    /**
     * 
     * @type {number}
     * @memberof Frontend
     */
    updatedAt?: number;
}

/**
 * Check if a given object implements the Frontend interface.
 */
export function instanceOfFrontend(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function FrontendFromJSON(json: any): Frontend {
    return FrontendFromJSONTyped(json, false);
}

export function FrontendFromJSONTyped(json: any, ignoreDiscriminator: boolean): Frontend {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'id': !exists(json, 'id') ? undefined : json['id'],
        'shrToken': !exists(json, 'shrToken') ? undefined : json['shrToken'],
        'zId': !exists(json, 'zId') ? undefined : json['zId'],
        'createdAt': !exists(json, 'createdAt') ? undefined : json['createdAt'],
        'updatedAt': !exists(json, 'updatedAt') ? undefined : json['updatedAt'],
    };
}

export function FrontendToJSON(value?: Frontend | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'id': value.id,
        'shrToken': value.shrToken,
        'zId': value.zId,
        'createdAt': value.createdAt,
        'updatedAt': value.updatedAt,
    };
}

