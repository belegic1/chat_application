import Head from 'next/head'
import styles from '../styles/Register.module.scss'
import { Container, Row, Col, Form, FormControl, FormGroup, FormLabel, Button } from "react-bootstrap"
import cls from "classnames"
import { useState } from 'react'

export default function Register() {

    const [variables, setVariables] = useState({
        email: "",
        username: "",
        password: "",
        confirmPassword: ""
    })

    const submitRegisterForm = e => {
        e.preventDefault()
        console.log(variables);
    }
    return (
        <div className={styles.container}>
            <Head>
                <title>Create Next App</title>
                <meta name="description" content="Generated by create next app" />
                <link rel="icon" href="/favicon.ico" />
            </Head>
            <Container className='pt-5'>
                <Row className={'bg-white py-5 justify-content-center'}>
                    <Col sm={8} md={6} lg={4}>
                        <h1 className={cls(styles.heading, 'text-center')}>Register</h1>
                        <Form onSubmit={submitRegisterForm}>
                            <FormGroup>
                                <FormLabel>
                                    Username
                                </FormLabel>
                                <FormControl type="text" value={variables.username} onChange={e => setVariables({
                                    ...variables, username: e.target.value
                                })} />
                            </FormGroup>

                            <FormGroup>
                                <FormLabel>
                                    Email Address
                                </FormLabel>
                                <FormControl type="email" value={variables.email} onChange={e => setVariables({
                                    ...variables, email: e.target.value
                                })} />
                            </FormGroup>

                            <FormGroup>
                                <FormLabel>
                                    Password
                                </FormLabel>
                                <FormControl type="password" value={variables.password} onChange={e => setVariables({
                                    ...variables, password: e.target.value
                                })} />
                            </FormGroup>

                            <FormGroup>
                                <FormLabel>
                                    Confirm Password
                                </FormLabel>
                                <FormControl type="password" value={variables.confirmPassword} onChange={e => setVariables({
                                    ...variables, confirmPassword: e.target.value
                                })} />
                            </FormGroup>

                            <div className="text-center mt-3">
                                <Button type="submit" variant="success">Register</Button>

                            </div>
                        </Form>
                    </Col>
                </Row>
            </Container>

        </div>
    )
}
