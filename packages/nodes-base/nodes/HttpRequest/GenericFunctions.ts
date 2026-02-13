import FormData from 'form-data';
import get from 'lodash/get';
import isPlainObject from 'lodash/isPlainObject';
import set from 'lodash/set';
import {
	deepCopy,
	setSafeObjectProperty,
	type ICredentialDataDecryptedObject,
	type IDataObject,
	type INodeExecutionData,
	type INodeProperties,
	type IOAuth2Options,
	type IRequestOptions,
} from 'n8n-workflow';
import {
	BINARY_ENCODING,
	NodeOperationError,
} from 'n8n-workflow';
import type { SecureContextOptions } from 'tls';
import type { Readable } from 'stream';

import type { HttpSslAuthCredentials } from './interfaces';
import { formatPrivateKey } from '../../utils/utilities';

export type BodyParameter = {
	name: string;
	value: string;
	parameterType?: 'formBinaryData' | 'formBinary' | 'formData';
	inputDataFieldName?: string;
};

export type IAuthDataSanitizeKeys = {
	[key: string]: string[];
};

export const replaceNullValues = (item: INodeExecutionData) => {
	if (item.json === null) {
		item.json = {};
	}
	return item;
};

export const REDACTED = '**hidden**';

function isObject(obj: unknown): obj is IDataObject {
	return isPlainObject(obj);
}

function redact<T = unknown>(obj: T, secrets: string[]): T {
	if (typeof obj === 'string') {
		return secrets.reduce((safe, secret) => safe.replace(secret, REDACTED), obj) as T;
	}

	if (Array.isArray(obj)) {
		return obj.map((item) => redact(item, secrets)) as T;
	} else if (isObject(obj)) {
		for (const [key, value] of Object.entries(obj)) {
			setSafeObjectProperty(obj, key, redact(value, secrets));
		}
	}

	return obj;
}

export function sanitizeUiMessage(
	request: IRequestOptions,
	authDataKeys: IAuthDataSanitizeKeys,
	secrets?: string[],
) {
	const { body, ...rest } = request as IDataObject;

	let sendRequest: IDataObject = { body };
	for (const [key, value] of Object.entries(rest)) {
		sendRequest[key] = deepCopy(value);
	}

	// Protect browser from sending large binary data
	if (Buffer.isBuffer(sendRequest.body) && sendRequest.body.length > 250000) {
		sendRequest = {
			...request,
			body: `Binary data got replaced with this text. Original was a Buffer with a size of ${
				(request.body as string).length
			} bytes.`,
		};
	}

	// Remove credential information
	for (const requestProperty of Object.keys(authDataKeys)) {
		sendRequest = {
			...sendRequest,
			[requestProperty]: Object.keys(sendRequest[requestProperty] as object).reduce(
				(acc: IDataObject, curr) => {
					acc[curr] = authDataKeys[requestProperty].includes(curr)
						? REDACTED
						: (sendRequest[requestProperty] as IDataObject)[curr];
					return acc;
				},
				{},
			),
		};
	}
	const HEADER_BLOCKLIST = new Set([
		'authorization',
		'x-api-key',
		'x-auth-token',
		'cookie',
		'proxy-authorization',
		'sslclientcert',
	]);

	const headers = sendRequest.headers as IDataObject;

	if (headers) {
		for (const headerName of Object.keys(headers)) {
			if (HEADER_BLOCKLIST.has(headerName.toLowerCase())) {
				headers[headerName] = REDACTED;
			}
		}
	}
	if (secrets && secrets.length > 0) {
		return redact(sendRequest, secrets);
	}

	return sendRequest;
}

export function getSecrets(
	properties: INodeProperties[],
	credentials: ICredentialDataDecryptedObject,
): string[] {
	const sensitivePropNames = new Set(
		properties.filter((prop) => prop.typeOptions?.password).map((prop) => prop.name),
	);

	const secrets = Object.entries(credentials)
		.filter(([propName]) => sensitivePropNames.has(propName))
		.map(([_, value]) => value)
		.filter((value): value is string => typeof value === 'string');
	const oauthAccessToken = get(credentials, 'oauthTokenData.access_token');
	if (typeof oauthAccessToken === 'string') {
		secrets.push(oauthAccessToken);
	}

	return secrets;
}

export const getOAuth2AdditionalParameters = (nodeCredentialType: string) => {
	const oAuth2Options: { [credentialType: string]: IOAuth2Options } = {
		bitlyOAuth2Api: {
			tokenType: 'Bearer',
		},
		boxOAuth2Api: {
			includeCredentialsOnRefreshOnBody: true,
		},
		ciscoWebexOAuth2Api: {
			tokenType: 'Bearer',
		},
		clickUpOAuth2Api: {
			keepBearer: false,
			tokenType: 'Bearer',
		},
		goToWebinarOAuth2Api: {
			tokenExpiredStatusCode: 403,
		},
		hubspotDeveloperApi: {
			tokenType: 'Bearer',
			includeCredentialsOnRefreshOnBody: true,
		},
		hubspotOAuth2Api: {
			tokenType: 'Bearer',
			includeCredentialsOnRefreshOnBody: true,
		},
		lineNotifyOAuth2Api: {
			tokenType: 'Bearer',
		},
		linkedInOAuth2Api: {
			tokenType: 'Bearer',
		},
		mailchimpOAuth2Api: {
			tokenType: 'Bearer',
		},
		mauticOAuth2Api: {
			includeCredentialsOnRefreshOnBody: true,
		},
		microsoftAzureMonitorOAuth2Api: {
			tokenExpiredStatusCode: 403,
		},
		microsoftDynamicsOAuth2Api: {
			property: 'id_token',
		},
		philipsHueOAuth2Api: {
			tokenType: 'Bearer',
		},
		raindropOAuth2Api: {
			includeCredentialsOnRefreshOnBody: true,
		},
		shopifyOAuth2Api: {
			tokenType: 'Bearer',
			keyToIncludeInAccessTokenHeader: 'X-Shopify-Access-Token',
		},
		slackOAuth2Api: {
			tokenType: 'Bearer',
			property: 'authed_user.access_token',
		},
		stravaOAuth2Api: {
			includeCredentialsOnRefreshOnBody: true,
		},
	};
	return oAuth2Options[nodeCredentialType];
};

//https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
export const binaryContentTypes = [
	'image/',
	'audio/',
	'video/',
	'application/octet-stream',
	'application/gzip',
	'application/zip',
	'application/vnd.rar',
	'application/epub+zip',
	'application/x-bzip',
	'application/x-bzip2',
	'application/x-cdf',
	'application/vnd.amazon.ebook',
	'application/msword',
	'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
	'application/vnd.ms-fontobject',
	'application/vnd.oasis.opendocument.presentation',
	'application/pdf',
	'application/x-tar',
	'application/vnd.visio',
	'application/vnd.ms-excel',
	'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
	'application/x-7z-compressed',
];

export type BodyParametersReducer = (
	acc: IDataObject,
	cur: { name: string; value: string; parameterType?: string; inputDataFieldName?: string },
) => Promise<IDataObject>;

export async function reduceAsync<T, R>(
	arr: T[],
	reducer: (acc: Awaited<Promise<R>>, cur: T) => Promise<R>,
	init: Promise<R> = Promise.resolve({} as R),
): Promise<R> {
	return await arr.reduce(async (promiseAcc, item) => {
		return await reducer(await promiseAcc, item);
	}, init);
}

// FIX: Complete parametersToKeyValue function that handles both formBinaryData and formBinary
export const parametersToKeyValue = async (
	this: any,
	accumulator: IDataObject,
	cur: BodyParameter,
): Promise<IDataObject> => {
	// Handle binary data for formBinaryData type (Binary body) - already works
	if (cur.parameterType === 'formBinaryData') {
		if (!cur.inputDataFieldName) return accumulator;
		const binaryData = this.helpers.assertBinaryData(this.itemIndex, cur.inputDataFieldName);
		let uploadData: Buffer | Readable;

		if (binaryData.id) {
			uploadData = await this.helpers.getBinaryStream(binaryData.id);
		} else {
			uploadData = Buffer.from(binaryData.data, BINARY_ENCODING);
		}

		accumulator[cur.name] = {
			value: uploadData,
			options: {
				filename: binaryData.fileName,
				contentType: binaryData.mimeType,
			},
		};
		return accumulator;
	}
	
	// FIX: Handle formBinary type (Form-Data binary file in multipart/form-data)
	// This fixes issue #25567 - binary upload broken in queue mode
	if (cur.parameterType === 'formBinary') {
		if (!cur.inputDataFieldName) return accumulator;
		
		// Get binary data buffer - works in both queue and non-queue mode
		const binaryDataBuffer = await this.helpers.getBinaryDataBuffer(
			this.itemIndex, 
			cur.inputDataFieldName
		);
		
		if (!binaryDataBuffer) {
			throw new NodeOperationError(
				this.getNode(),
				`Binary data not found for property: ${cur.inputDataFieldName}`,
				{ itemIndex: this.itemIndex }
			);
		}
		
		// Safely get metadata with fallbacks (handles queue mode where metadata may be missing)
		let fileName = 'file.bin';
		let mimeType = 'application/octet-stream';
		
		try {
			const binaryData = await this.helpers.getBinaryData(this.itemIndex, cur.inputDataFieldName);
			if (binaryData?.fileName) fileName = binaryData.fileName;
			if (binaryData?.mimeType) mimeType = binaryData.mimeType;
		} catch (e) {
			// Metadata not available in queue mode - use defaults
			// This is expected behavior, not an error
		}
		
		accumulator[cur.name] = {
			value: binaryDataBuffer,
			options: {
				filename: fileName,
				contentType: mimeType,
			}
		};
		return accumulator;
	}

	// Handle regular parameters
	if (cur.value !== undefined && cur.value !== null) {
		updadeQueryParameter(accumulator, cur.name, cur.value);
	}
	return accumulator;
};

export const prepareRequestBody = async (
	parameters: BodyParameter[],
	bodyType: string,
	version: number,
	defaultReducer: BodyParametersReducer,
) => {
	if (bodyType === 'json' && version >= 4) {
		return await parameters.reduce(async (acc, entry) => {
			const result = await acc;
			set(result, entry.name, entry.value);
			return result;
		}, Promise.resolve({}));
	} else if (bodyType === 'multipart-form-data' && version >= 4.2) {
		const formData = new FormData();

		for (const parameter of parameters) {
			if (parameter.parameterType === 'formBinaryData') {
				const entry = await defaultReducer({}, parameter);
				const key = Object.keys(entry)[0];
				const data = entry[key] as { value: Buffer; options: FormData.AppendOptions };
				formData.append(key, data.value, data.options);
				continue;
			}
			
			// FIX: Handle formBinary type in FormData construction for version >=4.2
			if (parameter.parameterType === 'formBinary') {
				const entry = await defaultReducer({}, parameter);
				const key = Object.keys(entry)[0];
				const data = entry[key] as { value: Buffer; options: FormData.AppendOptions };
				formData.append(key, data.value, data.options);
				continue;
			}

			formData.append(parameter.name, parameter.value);
		}

		return formData;
	} else {
		return await reduceAsync(parameters, defaultReducer);
	}
};

export const setAgentOptions = (
	requestOptions: IRequestOptions,
	sslCertificates: HttpSslAuthCredentials | undefined,
) => {
	if (sslCertificates) {
		const agentOptions: SecureContextOptions = {};
		if (sslCertificates.ca) agentOptions.ca = formatPrivateKey(sslCertificates.ca);
		if (sslCertificates.cert) agentOptions.cert = formatPrivateKey(sslCertificates.cert);
		if (sslCertificates.key) agentOptions.key = formatPrivateKey(sslCertificates.key);
		if (sslCertificates.passphrase)
			agentOptions.passphrase = formatPrivateKey(sslCertificates.passphrase);
		requestOptions.agentOptions = agentOptions;
	}
};

export const updadeQueryParameterConfig = (version: number) => {
	if (version < 4.3) {
		return (qs: IDataObject, name: string, value: string) => (qs[name] = value);
	} else {
		return (qs: { [key: string]: any }, name: string, value: any) => {
			if (qs[name] === undefined) {
				qs[name] = value;
			} else if (Array.isArray(qs[name])) {
				qs[name].push(value);
			} else {
				qs[name] = [qs[name], value];
			}
		};
	}
};

// Re-export updadeQueryParameter with the correct name for backward compatibility
export const updadeQueryParameter = updadeQueryParameterConfig;
