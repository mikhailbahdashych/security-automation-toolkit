export const hideEmail = (email: string) => {
  if (!email) return
  return email.split('@')[0].slice(0, 2) + '**' + '@**.'
    + email.split('.')[email.split('.').length - 1]
}
