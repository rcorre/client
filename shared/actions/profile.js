/* @flow */
import {navigateUp} from '../actions/router'
import * as Constants from '../constants/profile'
import type {AsyncAction} from '../constants/types/flux'
import {apiserverPostRpc} from '../constants/types/flow-types'

export function editProfile (bio: string, location: string, fullname: string) : AsyncAction {
  return function (dispatch) {
    dispatch({
      type: Constants.editingProfile,
      payload: {bio, location, fullname},
    })

    apiserverPostRpc({
      param: {
        endpoint: 'profile-edit',
        args: [
          {key: 'bio', value: bio},
          {key: 'location', value: location},
          {key: 'full_name', value: fullname},
        ],
      },
      incomingCallMap: {},
      callback: (error, status) => {
        // Flow is weird here, we have to give it true or false directly
        // instead of just giving it !!error
        if (error) {
          dispatch({
            type: Constants.editedProfile,
            payload: error,
            error: true,
          })
        } else {
          dispatch({
            type: Constants.editedProfile,
            payload: null,
            error: false,
          })
          dispatch(navigateUp())
        }
      },
    })
  }
}
