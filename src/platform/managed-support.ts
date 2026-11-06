/** Platform selection is injectable only by code; no environment bypass exists. */
export function assertManagedPlatform(platform:string=process.platform):void {
 if(platform!=='darwin'&&platform!=='linux')throw new Error('cloud_platform_unsupported');
}
