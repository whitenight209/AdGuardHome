import { SsoLogin } from 'panel/features/sso/SsoLogin';
import intl from 'panel/common/intl';

import { AuthLayout } from 'panel/common/ui/AuthLayout';
import { processLogin } from 'panel/stores/login';
import { Form, type LoginFormValues } from './Form';

export const Login = () => {
    const handleSubmit = (values: LoginFormValues) => {
        processLogin({ name: values.username, password: values.password });
    };

    return (
        <AuthLayout title={intl.getMessage('login')}>
            <SsoLogin>
                <Form onSubmit={handleSubmit} />
            </SsoLogin>
        </AuthLayout>
    );
};
