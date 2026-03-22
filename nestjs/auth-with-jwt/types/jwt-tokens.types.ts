export interface AccessTokenPayload {
  sub:string
}

export interface RefreshTokenPayload {
  sub:string,
  familyId:string,
  version:number
}
