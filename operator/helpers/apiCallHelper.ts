import axios, { AxiosRequestConfig, Method } from 'axios';

class ApiCallHelper {
    async apiCall(
        url: string = '',
        method: Method = 'GET',
        payload: Record<string, any> = {},
        headers: Record<string, string> = { 'Content-Type': 'application/json' },
        stringifyPayload: boolean = true
    ): Promise<any> {
        try {
            const options: AxiosRequestConfig = {
                method,
                url,
                timeout: 3 * 60 * 1000, // 3 minutes in milliseconds
                headers,
            };

            if (payload && Object.keys(payload).length > 0) {
                options.data = stringifyPayload ? JSON.stringify(payload) : payload;
            }

            const result = await axios(options);
            return result.data;
            
        } catch (error: any) {
            throw new Error(error.message);
        }
    }
}

export default new ApiCallHelper();
