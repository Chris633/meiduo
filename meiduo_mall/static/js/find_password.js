var vm = new Vue({
    el: '#app',
    // 修改Vue变量的读取语法，避免和django模板语法冲突
    delimiters: ['[[', ']]'],
    data: {
        host: host,

        image_code_id: '',
        image_code_url: '',

        username: '',
        image_code: '',
        mobile: '',
        access_token: '',
        sms_code: '',
        user_id: '',
        password: '',
        password2: '',

        // 发送短信的标志
        sending_flag: false,

        error_username: false,
        error_image_code: false,
        error_sms_code: false,

        error_username_message: '',
        error_image_code_message: '',
        sms_code_tip: '获取短信验证码',
        error_sms_code_message: '',
        error_password: false,
        error_check_password: false,

        // 控制表单显示
        is_show_form_1: true,
        is_show_form_2: false,
        is_show_form_3: false,
        is_show_form_4: false,

        // 控制进度条显示
        step_class: {
            'step-1': true,
            'step-2': false,
            'step-3': false,
            'step-4': false
        },
    },
    created: function () {
        this.generate_image_code();
    },
    methods: {
        // 生成uuid
        generate_uuid: function () {
            var d = new Date().getTime();
            if (window.performance && typeof window.performance.now === "function") {
                d += performance.now(); //use high-precision timer if available
            }
            var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
                var r = (d + Math.random() * 16) % 16 | 0;
                d = Math.floor(d / 16);
                return (c == 'x' ? r : (r & 0x3 | 0x8)).toString(16);
            });
            return uuid;
        },
        // 生成一个图片验证码的编号，并设置页面中图片验证码img标签的src属性
        generate_image_code: function () {
            // 生成一个编号
            // 严格一点的使用uuid保证编号唯一， 不是很严谨的情况下，也可以使用时间戳
            this.image_code_id = this.generate_uuid();

            // 设置页面中图片验证码img标签的src属性
            this.image_code_url = this.host + "/image_codes/" + this.image_code_id + "/";
        },
        // 检查数据
        check_username: function () {
            if (!this.username) {
                this.error_username_message = '请填写用户名或手机号';
                this.error_username = true;
            } else {
                this.error_username = false;
            }

        },
        check_image_code: function () {
            if (!this.image_code) {
                this.error_image_code_message = '请填写验证码';
                this.error_image_code = true;
            } else {
                this.error_image_code = false;
            }
        },
        check_sms_code: function () {
            if (!this.sms_code) {
                this.error_sms_code_message = '请填写短信验证码';
                this.error_sms_code = true;
            } else {
                this.error_sms_code = false;
            }
        },

        // 第一步表单提交, 获取手机号与发送短信的token
        form_1_on_submit: function () {
            this.check_username();
            this.check_image_code();

            if (this.error_username == false && this.error_image_code == false) {
                axios.get(this.host + '/accounts/' + this.username + '/sms/token/?image_code=' + this.image_code + '&image_code_id=' + this.image_code_id, {
                    responseType: 'json'
                })
                    .then(response => {

                        if (response.data.status == 5001) {
                            this.error_image_code_message = '图片验证码错误';
                            this.error_image_code = true;

                            
                        } else if (response.data.status == 5004) {
                            this.error_username_message = '用户名或手机号不存在';
                            this.error_username = true;

                            
                        }else{

                        this.mobile = response.data.mobile;
                        this.access_token = response.data.access_token;
                        this.step_class['step-2'] = true;
                        this.step_class['step-1'] = false;
                        this.is_show_form_1 = false;
                        this.is_show_form_2 = true;
                        }
                    })
                    .catch(error => {

                        console.log(error);

                    })
            }
        },

        // 第二步
        // 发送短信验证码
        send_sms_code: function () {
            if (this.sending_flag == true) {
                return;
            }
            this.sending_flag = true;

            axios.get(this.host + '/find_password_sms_codes/' + this.mobile + '?access_token=' + this.access_token, {
                responseType: 'json'
            })
                .then(response => {

                    if (response.data.status == 5001) {
                        this.error_sms_code_message = response.data.message;
                        this.error_sms_code = true;
                        return
                    }

                    // 表示后端发送短信成功
                    // 倒计时60秒，60秒后允许用户再次点击发送短信验证码的按钮
                    var num = 60;
                    // 设置一个计时器
                    var t = setInterval(() => {
                        if (num == 1) {
                            // 如果计时器到最后, 清除计时器对象
                            clearInterval(t);
                            // 将点击获取验证码的按钮展示的文本回复成原始文本
                            this.sms_code_tip = '获取短信验证码';
                            // 将点击按钮的onclick事件函数恢复回去
                            this.sending_flag = false;
                        } else {
                            num -= 1;
                            // 展示倒计时信息
                            this.sms_code_tip = num + '秒';
                        }
                    }, 1000, 60)

                    if (response.data.status == 5000) {
                        alert(response.data.message)
                    }
                })
                .catch(error => {
                    alert(error);
                    this.sending_flag = false;
                })
        },
        // 第二步表单提交，验证手机号，获取修改密码的access_token
        form_2_on_submit: function () {
            this.check_sms_code();
            if (this.error_sms_code == false) {
                axios.get(this.host + '/accounts/' + this.mobile + '/password/token/?sms_code=' + this.sms_code, {
                    responseType: 'json'
                })
                    .then(response => {

                        if (response.data.status == 5001) {
                            this.error_sms_code_message = '验证码错误';
                            this.error_sms_code = true;

                            

                        } else if (response.data.status == 5004) {
                            this.error_sms_code_message = '手机号不存在';
                            this.error_sms_code = true;
                            
                        }else{

                        this.user_id = response.data.user_id;
                        this.access_token = response.data.access_token;
                        this.step_class['step-3'] = true;
                        this.step_class['step-2'] = false;
                        this.is_show_form_2 = false;
                        this.is_show_form_3 = true;
                        }
                    })
                    .catch(error => {

                        alert(error);

                    })
            }
        },

        // 第三步
        check_pwd: function () {
            var len = this.password.length;
            if (len < 8 || len > 20) {
                this.error_password = true;
            } else {
                this.error_password = false;
            }
        },
        check_cpwd: function () {
            if (this.password != this.password2) {
                this.error_check_password = true;
            } else {
                this.error_check_password = false;
            }
        },
        getCookie (name) {
            var value = '; ' + document.cookie
            var parts = value.split('; ' + name + '=')
            if (parts.length === 2) return parts.pop().split(';').shift()
        },

        form_3_on_submit: function () {
            this.check_pwd();
            this.check_cpwd();
            let CSRFToken = this.getCookie('csrftoken')
            if (this.error_password == false && this.error_check_password == false) {
                axios.post(this.host + '/users/' + this.user_id + '/new_password/',
                    {
                        password: this.password,
                        password2: this.password2,
                        access_token: this.access_token
                    }, {
                        headers: {'X-CSRFToken': CSRFToken},
                        responseType: 'json'
                    })
                    .then(response => {

                         if (response.data.status == 5001) {
                            alert(response.data.message)
                            

                        } else if (response.data.status == 5002) {
                            alert(response.data.message)
                            
                        }else{

                            this.step_class['step-4'] = true;
                            this.step_class['step-3'] = false;
                            this.is_show_form_3 = false;
                            this.is_show_form_4 = true;

                            //修改成功重定向到登录页
                            setTimeout(function () {
                                location.href="/login/"
                            },1000)

                        }
                    })
                    .catch(error => {
                        alert(error);

                    })
            }
        }
    }
})